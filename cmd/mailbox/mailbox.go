package main

import (
	"crypto/ecdsa"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/kwonalbert/xrd/config"
	"github.com/kwonalbert/xrd/mailbox"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	addr        = flag.String("addr", "localhost:9000", "Address of this mailbox")
	mailboxFile = flag.String("mailboxes", "mailbox.config", "Mailbox configuration file name")
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()

	mcfgs, err := config.UnmarshalServersFromFile(*mailboxFile)
	if err != nil {
		log.Fatal(err)
	}

	var coordinator ecdsa.PublicKey

	mb := mailbox.NewMailboxServer(coordinator)

	cred := credentials.NewServerTLSFromCert(config.FindCertificate(*addr, mcfgs))
	grpcServer := grpc.NewServer(grpc.Creds(cred),
		grpc.MaxRecvMsgSize(2*config.StreamSize), grpc.MaxSendMsgSize(2*config.StreamSize))
	mailbox.RegisterMailboxServer(grpcServer, mb)

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
