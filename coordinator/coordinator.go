package coordinator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"runtime/debug"
	"time"

	"github.com/kwonalbert/xrd/client"
	"github.com/kwonalbert/xrd/config"
	"github.com/kwonalbert/xrd/mailbox"
	"github.com/kwonalbert/xrd/server"
	"github.com/kwonalbert/xrd/span"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type Coordinator interface {
	PublicKey() ecdsa.PublicKey
	NewRound(round, numUsers int) error
	GenerateMessages(round, msgSize int) error
	SubmitMessages(round int) error
	StartExperiment(round int) error
}

type coordinator struct {
	key *ecdsa.PrivateKey

	mailboxes map[string]*config.Server
	clients   map[string]*config.Server
	servers   map[string]*config.Server
	groups    map[string]*config.Group
}

func NewCoordinator(mailboxes, clients, servers map[string]*config.Server, groups map[string]*config.Group) Coordinator {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("Could not generate ecdsa key")
	}

	c := &coordinator{
		key: key,

		mailboxes: mailboxes,
		clients:   clients,
		servers:   servers,
		groups:    groups,
	}
	return c
}

func (coord *coordinator) PublicKey() ecdsa.PublicKey {
	return coord.key.PublicKey
}

func (coord *coordinator) NewRound(round, numUsers int) error {
	mconss, err := config.DialServers(coord.mailboxes)
	if err != nil {
		log.Println("Could not dial mailbox")
		return err
	}
	cconss, err := config.DialServers(coord.clients)
	if err != nil {
		log.Println("Could not dial clients")
		return err
	}
	sconss, err := config.DialServers(coord.servers)
	if err != nil {
		log.Println("Could not dial clients")
		return err
	}

	defer config.CloseConns(mconss)
	defer config.CloseConns(cconss)
	defer config.CloseConns(sconss)

	for id, cfg := range coord.mailboxes {
		rpc := mailbox.NewMailboxClient(mconss[cfg.Address])
		md := metadata.Pairs(
			"id", id,
		)
		ctx := metadata.NewOutgoingContext(context.Background(), md)
		_, err := rpc.NewRound(ctx, &mailbox.NewRoundRequest{
			Round: uint64(round),
		})
		if err != nil {
			log.Println("Mailbox failed to start a new round")
			return err
		}
	}

	spans := span.NSpans(numUsers, len(coord.clients))

	i := 0
	errs := make(chan error, len(coord.clients)+len(sconss))
	for _, cfg := range coord.clients {
		go func(i int, cfg *config.Server) {
			rpc := client.NewClientClient(cconss[cfg.Address])
			_, err := rpc.RegisterUsers(context.Background(), &client.RegisterUsersRequest{
				Round:    uint64(round),
				NumUsers: uint64(spans[i].End - spans[i].Start),
			})
			errs <- err
		}(i, cfg)
		i++
	}

	for i := 0; i < len(coord.clients); i++ {
		err := <-errs
		if err != nil {
			return err
		}
	}

	log.Println("Users registered")

	// there should only be one server per address,
	// so loop through sconss rather than coord.servers
	for _, cc := range sconss {
		go func(cc *grpc.ClientConn) {
			rpc := server.NewXRDClient(cc)
			_, err := rpc.NewRound(context.Background(), &server.NewRoundRequest{
				Round: uint64(round),
			})
			if err != nil {
				log.Println("Server failed to start a new round:", err)
				errs <- err
			} else {
				errs <- nil
			}
		}(cc)
	}

	for i := 0; i < len(sconss); i++ {
		err := <-errs
		if err != nil {
			return err
		}
	}

	log.Println("New round created")

	return nil
}

func (coord *coordinator) GenerateMessages(round, msgSize int) error {
	cconss, err := config.DialServers(coord.clients)
	if err != nil {
		return err
	}
	defer config.CloseConns(cconss)

	start := time.Now()

	i := 0
	errs := make(chan error, len(coord.clients))
	for _, cfg := range coord.clients {
		go func(i int, addr string) {
			rpc := client.NewClientClient(cconss[addr])
			_, err := rpc.GenerateMessages(context.Background(), &client.GenerateMessagesRequest{
				Round:   uint64(round),
				MsgSize: uint64(msgSize),
			})
			if err != nil {
				log.Println(addr, "err:", err)
			}
			errs <- err
		}(i, cfg.Address)
		i++
	}

	for i := 0; i < len(coord.clients); i++ {
		err := <-errs
		if err != nil {
			return err
		}
	}

	fmt.Println("Generation took:", time.Since(start))
	debug.FreeOSMemory()
	return nil
}

func (coord *coordinator) SubmitMessages(round int) error {
	cconss, err := config.DialServers(coord.clients)
	if err != nil {
		return err
	}

	defer config.CloseConns(cconss)

	start := time.Now()

	errs := make(chan error, len(coord.clients))
	for _, cfg := range coord.clients {
		go func(addr string) {
			rpc := client.NewClientClient(cconss[addr])
			_, err := rpc.SubmitMessages(context.Background(), &client.SubmitMessagesRequest{
				Round: uint64(round),
			})
			if err != nil {
				log.Println("Could not dial client")
			}
			errs <- err
		}(cfg.Address)
	}
	for i := 0; i < len(coord.clients); i++ {
		err := <-errs
		if err != nil {
			return err
		}
	}
	log.Println("Submission took:", time.Since(start))
	debug.FreeOSMemory()
	return nil
}

func (coord *coordinator) StartExperiment(round int) error {
	sconss, err := config.DialServers(coord.servers)
	if err != nil {
		return err
	}

	cconss, err := config.DialServers(coord.clients)
	if err != nil {
		return err
	}

	defer config.CloseConns(sconss)
	defer config.CloseConns(cconss)

	start := time.Now()

	errs := make(chan error, len(coord.clients)+len(sconss))
	for _, cc := range sconss {
		go func(cc *grpc.ClientConn) {
			rpc := server.NewXRDClient(cc)
			_, err := rpc.StartRound(context.Background(), &server.StartRoundRequest{
				Round: uint64(round),
			})
			if err != nil {
				log.Println("Could not dial server")
			}
			errs <- err
		}(cc)
	}

	for _, cfg := range coord.clients {
		go func(cfg *config.Server) {
			rpc := client.NewClientClient(cconss[cfg.Address])
			_, err := rpc.DownloadMessages(context.Background(), &client.DownloadMessagesRequest{
				Round: uint64(round),
			})
			if err != nil {
				log.Println("Could not dial client for download")
			}
			errs <- err
		}(cfg)
	}

	for i := 0; i < len(sconss)+len(coord.clients); i++ {
		err := <-errs
		if err != nil {
			return err
		}
	}

	fmt.Println("Experiment took:", time.Since(start))
	debug.FreeOSMemory()

	for _, cc := range sconss {
		go func(cc *grpc.ClientConn) {
			rpc := server.NewXRDClient(cc)
			_, err := rpc.EndRound(context.Background(), &server.EndRoundRequest{
				Round: uint64(round),
			})
			errs <- err
		}(cc)
	}

	for i := 0; i < len(sconss); i++ {
		err := <-errs
		if err != nil {
			return err
		}
	}

	return nil
}
