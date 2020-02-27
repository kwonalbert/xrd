package mixnet

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kwonalbert/xrd/config"
	"github.com/kwonalbert/mixnet"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

func serverAddr(idx int) string {
	return fmt.Sprintf("localhost:%d", 8000+idx)
}

func port(addr string) string {
	return ":" + strings.Split(addr, ":")[1]
}

func createMixnetConfigs(n int) (map[string]*config.Server, *config.Group) {
	servers := make(map[string]*config.Server)
	gid := "group:0"
	group := &config.Group{
		Gid:     gid,
		Layer:   0,
		Row:     0,
		Servers: make([]string, n),
	}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("server:%d", i)
		addr := serverAddr(i)
		server := config.CreateServer(addr, id)
		servers[id] = server
		group.Servers[i] = id
	}
	return servers, group
}

func findCertificate(addr string, servers map[string]*config.Server) *tls.Certificate {
	for _, server := range servers {
		if server.Address != addr {
			continue
		}
		c, err := tls.X509KeyPair(server.Identity, server.PrivateIdentity)
		if err != nil {
			panic(err)
		}
		return &c
	}
	return nil
}

func createMixnet(coordinator ecdsa.PublicKey, servers map[string]*config.Server, groups map[string]*config.Group) []MixServer {
	mixes := make([]MixServer, len(servers))
	for i := range mixes {
		mixes[i] = NewMixServer(serverAddr(i), coordinator, servers, groups)
	}
	for i := range mixes {
		lis, err := net.Listen("tcp", port(serverAddr(i)))
		if err != nil {
			log.Fatal("Could not listen:", err)
		}

		cred := credentials.NewServerTLSFromCert(findCertificate(serverAddr(i), servers))
		grpcServer := grpc.NewServer(grpc.Creds(cred))
		RegisterMixServer(grpcServer, mixes[i])

		go func() {
			err := grpcServer.Serve(lis)
			if err != grpc.ErrServerStopped {
				log.Fatal("Serve err:", err)
			}
		}()
	}
	time.Sleep(100)

	return mixes
}

func createTestCiphertexts(num int, servers map[string]*config.Server, group *config.Group) ([][]byte, [][]byte, [][]byte) {
	n := len(group.Servers)
	msgs := make([][]byte, 10)
	ciphertexts := make([][]byte, len(msgs))
	prfs := make([][]byte, len(msgs))
	auxs := make([][]byte, n)
	nonces := make([][]byte, n)
	for i := range nonces {
		nonce := mixnet.Nonce(0, int(group.Row), i)
		nonces[i] = nonce[:]
	}

	publicKeys := make([][]byte, n)
	for s, sid := range group.Servers {
		publicKeys[s] = servers[sid].PublicKey
	}

	for i := range msgs {
		msgs[i] = make([]byte, 10)
		rand.Read(msgs[i])

		ciphertexts[i], prfs[i] = mixnet.P256OnionEncrypt(msgs[i], auxs, nonces, publicKeys, true)
	}

	return msgs, ciphertexts, prfs
}

func TestMixnet(t *testing.T) {
	coordinator, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("Could not generate ecdsa key")
	}
	n := 3
	servers, group := createMixnetConfigs(n)
	groups := make(map[string]*config.Group)
	groups[group.Gid] = group

	mixes := createMixnet(coordinator.PublicKey, servers, groups)

	expected, ciphertexts, prfs := createTestCiphertexts(1, servers, group)

	pool := x509.NewCertPool()
	for m := range mixes {
		mix := servers[group.Servers[m]]
		pool.AppendCertsFromPEM(mix.Identity)
	}
	creds := credentials.NewClientTLSFromCert(pool, "")
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}

	mixClients := make([]MixClient, len(mixes))
	for m := range mixes {
		conn, err := grpc.Dial(serverAddr(m), opts...)
		if err != nil {
			t.Error(err)
		}
		mixClients[m] = NewMixClient(conn)
		mixClients[m].NewRound(context.Background(), &NewRoundRequest{Round: 0})
	}

	// submit messages to all servers
	for m := range mixes {
		md := metadata.Pairs(
			"id", group.Servers[m],
			"round", strconv.Itoa(0),
		)
		ctx := metadata.NewOutgoingContext(context.Background(), md)

		stream, err := mixClients[m].SubmitCiphertexts(ctx)
		if err != nil {
			t.Error(err)
		}

		req := &SubmitCiphertextsRequest{
			Round:       0,
			Ciphertexts: ciphertexts,
			Proofs:      prfs,
		}
		err = stream.Send(req)
		if err != nil {
			t.Error(err)
		}
		_, err = stream.CloseAndRecv()
		if err != nil && err != io.EOF {
			t.Error(err)
		}
	}

	errs := make(chan error, len(mixClients))
	for m := range mixClients {
		go func(m int) {
			md := metadata.Pairs(
				"id", group.Servers[m],
			)
			ctx := metadata.NewOutgoingContext(context.Background(), md)

			_, err = mixClients[m].StartRound(ctx, &StartRoundRequest{
				Round: 0,
			})
			errs <- err
		}(m)
	}
	for range mixClients {
		err := <-errs
		if err != nil {
			t.Error(err)
		}
	}

	log.Println("Started round")

	mdn := metadata.Pairs(
		"id", group.Servers[len(group.Servers)-1],
	)
	ctxn := metadata.NewOutgoingContext(context.Background(), mdn)
	resp, err := mixClients[len(mixClients)-1].GetMessages(ctxn, &GetMessagesRequest{
		Round: 0,
	})

	if err != nil {
		t.Error(err)
	}

	for _, res := range resp.Messages {
		found := false
		for _, exp := range expected {
			if bytes.Equal(exp, res) {
				found = true
				break
			}
		}
		if !found {
			t.Error("Missing messages after mixing")
		}
	}
}
