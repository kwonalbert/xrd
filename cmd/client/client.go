package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/kwonalbert/xrd/client"
	"github.com/kwonalbert/xrd/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	addr        = flag.String("addr", "localhost:10000", "Address of this client")
	serverFile  = flag.String("servers", "server.config", "Server configuration file name")
	groupFile   = flag.String("groups", "group.config", "Group configuration file name")
	mailboxFile = flag.String("mailboxes", "mailbox.config", "Mailbox configuration file name")
	clientFile  = flag.String("clients", "client.config", "Client configuration file name")
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()

	scfgs, err := config.UnmarshalServersFromFile(*serverFile)
	if err != nil {
		log.Fatal(err)
	}
	gcfgs, err := config.UnmarshalGroupsFromFile(*groupFile)
	if err != nil {
		log.Fatal(err)
	}
	mcfgs, err := config.UnmarshalServersFromFile(*mailboxFile)
	if err != nil {
		log.Fatal(err)
	}
	ccfgs, err := config.UnmarshalServersFromFile(*clientFile)
	if err != nil {
		log.Fatal(err)
	}

	clt := client.NewClient(mcfgs, scfgs, gcfgs)

	cred := credentials.NewServerTLSFromCert(config.FindCertificate(*addr, ccfgs))
	grpcServer := grpc.NewServer(grpc.Creds(cred),
		grpc.MaxRecvMsgSize(2*config.StreamSize), grpc.MaxSendMsgSize(2*config.StreamSize))
	client.RegisterClientServer(grpcServer, clt)

	lis, err := net.Listen("tcp", config.Port(*addr))
	if err != nil {
		log.Fatal("Could not listen:", *addr, err)
	}

	go func() {
		err = grpcServer.Serve(lis)
		if err != grpc.ErrServerStopped {
			log.Fatal("Serve err:", err)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	grpcServer.Stop()
}
