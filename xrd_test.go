package xrd

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"net"
	"os"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/kwonalbert/xrd/client"
	"github.com/kwonalbert/xrd/config"
	"github.com/kwonalbert/xrd/coordinator"
	"github.com/kwonalbert/xrd/mailbox"
	"github.com/kwonalbert/xrd/mixnet"
	"github.com/kwonalbert/xrd/server"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Should call defer pprof.StopCPUProfile() for the test as well
var cpuprofile = "cpuprofile"

func profile() {
	if cpuprofile != "" {
		f, err := os.Create(cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
	}
}

func serverAddr(idx int) string {
	return fmt.Sprintf("localhost:%d", 8000+idx)
}

func mailboxAddr(idx int) string {
	return fmt.Sprintf("localhost:%d", 8500+idx)
}

func clientAddr(idx int) string {
	return fmt.Sprintf("localhost:%d", 9000+idx)
}

func port(addr string) string {
	return ":" + strings.Split(addr, ":")[1]
}

func createMailboxes(coordinator ecdsa.PublicKey, mcfgs map[string]*config.Server) map[string]mailbox.MailboxServer {
	mailboxes := make(map[string]mailbox.MailboxServer)
	for id := range mcfgs {
		mailboxes[id] = mailbox.NewMailboxServer(coordinator)
	}
	for id, cfg := range mcfgs {
		go func(id string, cfg *config.Server) {
			cred := credentials.NewServerTLSFromCert(config.FindCertificate(cfg.Address, mcfgs))
			grpcServer := grpc.NewServer(grpc.Creds(cred))
			mailbox.RegisterMailboxServer(grpcServer, mailboxes[id])

			lis, err := net.Listen("tcp", port(cfg.Address))
			if err != nil {
				log.Fatal("Could not listen:", cfg.Address, err)
			}

			err = grpcServer.Serve(lis)
			if err != grpc.ErrServerStopped {
				log.Fatal("Serve err:", err)
			}
		}(id, cfg)
	}
	time.Sleep(time.Millisecond)

	return mailboxes
}

func createClients(ccfgs, mcfgs, scfgs map[string]*config.Server, gcfgs map[string]*config.Group) map[string]client.ClientServer {
	clients := make(map[string]client.ClientServer)
	for id := range ccfgs {
		clients[id] = client.NewClient(mcfgs, scfgs, gcfgs)
	}

	for id, cfg := range ccfgs {
		go func(id string, cfg *config.Server) {
			cred := credentials.NewServerTLSFromCert(config.FindCertificate(cfg.Address, ccfgs))
			grpcServer := grpc.NewServer(grpc.Creds(cred))
			client.RegisterClientServer(grpcServer, clients[id])

			lis, err := net.Listen("tcp", port(cfg.Address))
			if err != nil {
				log.Fatal("Could not listen:", cfg.Address, err)
			}

			err = grpcServer.Serve(lis)
			if err != grpc.ErrServerStopped {
				log.Fatal("Serve err:", err)
			}
		}(id, cfg)
	}
	time.Sleep(time.Millisecond)

	return clients
}

func createServers(coordinator ecdsa.PublicKey, mcfgs, scfgs map[string]*config.Server, gcfgs map[string]*config.Group) map[string]server.XRDServer {
	// only one server per adddress
	servers := make(map[string]server.XRDServer)
	mixes := make(map[string]mixnet.MixServer)
	for _, cfg := range scfgs {
		addr := cfg.Address
		if _, ok := servers[addr]; ok {
			continue
		}
		mixes[addr] = mixnet.NewMixServer(cfg.Address, coordinator, scfgs, gcfgs)
		servers[addr] = server.NewServer(cfg.Address, coordinator, mcfgs, scfgs, gcfgs, mixes[addr])
	}

	for addr := range servers {
		go func(addr string) {
			cred := credentials.NewServerTLSFromCert(config.FindCertificate(addr, scfgs))

			grpcServer := grpc.NewServer(grpc.Creds(cred))
			mixnet.RegisterMixServer(grpcServer, mixes[addr])
			server.RegisterXRDServer(grpcServer, servers[addr])

			lis, err := net.Listen("tcp", port(addr))
			if err != nil {
				log.Fatal("Could not listen:", addr, err)
			}

			err = grpcServer.Serve(lis)
			if err != grpc.ErrServerStopped {
				log.Fatal("Serve err:", err)
			}
		}(addr)
	}
	time.Sleep(time.Millisecond)

	return servers
}

func createNetworkConfig(numBoxes, numClients, groupSize, numGroups int) (map[string]*config.Server, map[string]*config.Server, map[string]*config.Server, map[string]*config.Group) {
	clients := make(map[string]*config.Server)
	for c := 0; c < numClients; c++ {
		cid := fmt.Sprintf("client:%d", c)
		clients[cid] = config.CreateServerWithExisting(clientAddr(c), cid, clients)
	}

	mailboxes := make(map[string]*config.Server)
	for m := 0; m < numBoxes; m++ {
		mid := fmt.Sprintf("mailbox:%d", m)
		mailboxes[mid] = config.CreateServerWithExisting(mailboxAddr(m), mid, mailboxes)
	}

	servers := make(map[string]*config.Server)
	groups := make(map[string]*config.Group)
	for g := 0; g < numGroups; g++ {
		gid := fmt.Sprintf("group:%d", g)
		group := &config.Group{
			Gid:     gid,
			Layer:   0,
			Row:     uint32(g),
			Servers: make([]string, groupSize),
		}
		for i := 0; i < groupSize; i++ {
			id := fmt.Sprintf("server:(%d,%d)", g, i)
			server := config.CreateServerWithExisting(serverAddr(i), id, servers)
			servers[id] = server
			group.Servers[i] = id
		}
		groups[gid] = group
	}
	return mailboxes, clients, servers, groups
}

func TestXRD(t *testing.T) {
	numMailboxes := 2
	numClients := 2
	groupSize := 8
	numGroups := 4
	numUsers := 1000
	msgSize := 256

	mcfgs, ccfgs, scfgs, gcfgs := createNetworkConfig(numMailboxes, numClients, groupSize, numGroups)

	coordinator := coordinator.NewCoordinator(mcfgs, ccfgs, scfgs, gcfgs)

	createMailboxes(coordinator.PublicKey(), mcfgs)
	createServers(coordinator.PublicKey(), mcfgs, scfgs, gcfgs)
	createClients(ccfgs, mcfgs, scfgs, gcfgs)

	for i := 0; i < 2; i++ {
		log.Println("Setup new rounds")
		err := coordinator.NewRound(i, numUsers)
		if err != nil {
			t.Error(err)
		}

		log.Println("Generate messages")
		err = coordinator.GenerateMessages(i, msgSize)
		if err != nil {
			t.Error(err)
		}

		// profile()
		// defer pprof.StopCPUProfile()
		log.Println("Submit messages")
		err = coordinator.SubmitMessages(i)
		if err != nil {
			t.Error(err)
		}

		log.Println("Start routing")
		err = coordinator.StartExperiment(i)
		if err != nil {
			t.Error(err)
		}
	}
}
