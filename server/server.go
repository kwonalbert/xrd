package server

import (
	"crypto/ecdsa"
	"io"
	"log"
	"runtime/debug"
	"time"

	"github.com/kwonalbert/xrd/config"
	"github.com/kwonalbert/xrd/mailbox"
	"github.com/kwonalbert/xrd/mixnet"
	"github.com/kwonalbert/xrd/span"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"golang.org/x/net/context"
)

type server struct {
	addr string

	mix mixnet.MixServer

	servers     map[string]*config.Server
	mailboxes   map[string]*config.Server
	groups      map[string]*config.Group
	myServers   map[string]*config.Server
	lastServers map[string]*config.Server

	rerrs map[int]chan error

	mconns map[string]*grpc.ClientConn
	mrpcs  map[string]mailbox.MailboxClient

	start time.Time
}

// addr: the physical address of this server
// coordinator: the public key of the coordinator server
// servers: map (list) of all server configurations
// groups: map (list) of all group configurations
// mailboxes: map (list) of all mailboxes
func NewServer(addr string, coordinator ecdsa.PublicKey, mailboxes, servers map[string]*config.Server, groups map[string]*config.Group, mix mixnet.MixServer) XRDServer {
	myServers := make(map[string]*config.Server)
	lastServers := make(map[string]*config.Server)
	for _, group := range groups {
		for s, sid := range group.Servers {
			server := servers[sid]

			if server.Address == addr {
				myServers[sid] = server
			}
			if server.Address == addr && s == len(group.Servers)-1 {
				lastServers[sid] = server
			}
		}
	}

	s := &server{
		addr: addr,

		mix: mix,

		servers:     servers,
		mailboxes:   mailboxes,
		groups:      groups,
		myServers:   myServers,
		lastServers: lastServers,

		rerrs: make(map[int]chan error),
	}
	return s
}

func (srv *server) dialOnce() error {
	conns, err := config.DialServers(srv.mailboxes)
	if err != nil {
		return err
	}
	rpcs := make(map[string]mailbox.MailboxClient)
	for mid, cfg := range srv.mailboxes {
		rpcs[mid] = mailbox.NewMailboxClient(conns[cfg.Address])
	}

	srv.mconns = conns
	srv.mrpcs = rpcs

	return nil
}

// only called for the last servers in the chain
func (srv *server) handleRound(round uint64, server *config.Server, mailboxMap map[[32]byte]string) error {
	md := metadata.Pairs(
		"id", server.Id,
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	// get all the shuffled inner ciphertexts
	resp, err := srv.mix.GetMessages(ctx, &mixnet.GetMessagesRequest{
		Round: uint64(round),
	})
	if err != nil {
		log.Fatal("Get message should never return an error here:", err)
	}
	inners := resp.Messages

	// start the envelope protocol
	_, err = srv.mix.AddInnerCiphertexts(ctx, &mixnet.AddInnerCiphertextsRequest{
		Round:    round,
		Messages: inners,
	})
	if err != nil {
		log.Fatal("Get message should never return an error here:", err)
	}

	mixingTime := time.Since(srv.start)

	// recover the plaintext msgs
	final, err := srv.mix.Finalize(ctx, &mixnet.FinalizeRequest{
		Round: uint64(round),
	})
	if err != nil { // handle the error correctly..
		log.Println("Finalize error:", err)
		return err
	}

	// send the mails to their final mailbox server
	mails := make(map[string][]*mailbox.Mail)
	for mid := range srv.mailboxes {
		mails[mid] = nil
	}

	var tmpKey [32]byte
	for _, msg := range final.Plaintexts {
		mail := mailbox.UnmarshalMail(msg)
		copy(tmpKey[:], mail.UserKey)
		dst := mailboxMap[tmpKey]
		mails[dst] = append(mails[dst], mail)
	}

	for mid, ms := range mails {
		go func(mid string, ms []*mailbox.Mail) {
			if len(ms) < 1 { // no message going to that mailbox
				return
			}
			spans := span.StreamSpan(len(ms), config.StreamSize, len(ms[0].Message)+32)

			stream, err := srv.mrpcs[mid].DeliverMails(context.Background())
			if err != nil {
				log.Println("Could not create stream to mailbox:", err)
			}

			for _, span := range spans {
				req := &mailbox.DeliverMailsRequest{
					Round: round,
					Mails: ms[span.Start:span.End],
				}

				err = stream.Send(req)
				if err != nil {
					log.Println("Could not stream to mailbox:", err)
				}
			}
			_, err = stream.CloseAndRecv()
			if err != nil && err != io.EOF {
				log.Println("Error in closing mailbox stream:", err)
			}

			//log.Println(server.Id + " delivery complete to " + mid + ".")
		}(mid, ms)
	}

	log.Println(server.Address, server.Id, "mixing and verifying", len(final.Plaintexts), "msgs took:", mixingTime, time.Since(srv.start))

	return nil
}

func (srv *server) NewRound(ctx context.Context, in *NewRoundRequest) (*NewRoundResponse, error) {
	if err := srv.dialOnce(); err != nil {
		return nil, err
	}

	_, err := srv.mix.NewRound(context.Background(), &mixnet.NewRoundRequest{
		Round: in.Round,
	})
	if err != nil {
		return nil, err
	}

	var tmpKey [32]byte
	mailboxMap := make(map[[32]byte]string)
	for mid, rpc := range srv.mrpcs {
		req := &mailbox.RegisteredUsersRequest{
			Round: in.Round,
		}
		stream, err := rpc.RegisteredUsers(context.Background(), req)
		if err != nil {
			return nil, err
		}

		var keys [][]byte
		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}
			keys = append(keys, resp.UserKeys...)
		}

		for _, key := range keys {
			copy(tmpKey[:], key)
			mailboxMap[tmpKey] = mid
		}
	}

	errs := make(chan error, len(srv.lastServers))
	srv.rerrs[int(in.Round)] = errs

	for _, server := range srv.lastServers {
		go func(server *config.Server) {
			errs <- srv.handleRound(in.Round, server, mailboxMap)
		}(server)
	}
	return &NewRoundResponse{}, nil
}

func (srv *server) EndRound(ctx context.Context, in *EndRoundRequest) (*EndRoundResponse, error) {
	errs := srv.rerrs[int(in.Round)]
	for range srv.lastServers {
		<-errs
	}

	_, err := srv.mix.EndRound(context.Background(), &mixnet.EndRoundRequest{
		Round: in.Round,
	})
	if err != nil {
		return nil, err
	}

	debug.FreeOSMemory()

	return &EndRoundResponse{}, nil
}

func (srv *server) StartRound(ctx context.Context, in *StartRoundRequest) (*StartRoundResponse, error) {
	srv.start = time.Now()

	errs := make(chan error, len(srv.myServers))
	for _, server := range srv.myServers {
		go func(server *config.Server) {
			md := metadata.Pairs(
				"id", server.Id,
			)
			ctx := metadata.NewIncomingContext(context.Background(), md)
			_, err := srv.mix.StartRound(ctx, &mixnet.StartRoundRequest{
				Round: in.Round,
			})
			errs <- err
		}(server)
	}

	for range srv.myServers {
		err := <-errs
		if err != nil {
			return nil, err
		}
	}

	return &StartRoundResponse{}, nil
}
