package main

import (
	"crypto/ecdsa"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	// "net/http"
	// _ "net/http/pprof"
	// "runtime"

	"github.com/kwonalbert/xrd/config"
	"github.com/kwonalbert/xrd/mixnet"
	"github.com/kwonalbert/xrd/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	addr        = flag.String("addr", "localhost:8000", "Address of this server")
	serverFile  = flag.String("servers", "server.config", "Server configuration file name")
	groupFile   = flag.String("groups", "group.config", "Group configuration file name")
	mailboxFile = flag.String("mailboxes", "mailbox.config", "Mailbox configuration file name")
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()

	// go func() {
	// 	runtime.SetBlockProfileRate(1)
	// 	runtime.SetMutexProfileFraction(1)
	// 	log.Println(http.ListenAndServe(":6060", nil))
	// }()

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

	// TODO: generate and provide appropriate coordinator key
	var coordinator ecdsa.PublicKey

	mixer := mixnet.NewMixServer(*addr, coordinator, scfgs, gcfgs)
	serv := server.NewServer(*addr, coordinator, mcfgs, scfgs, gcfgs, mixer)

	cred := credentials.NewServerTLSFromCert(config.FindCertificate(*addr, scfgs))
	grpcServer := grpc.NewServer(grpc.Creds(cred),
		grpc.MaxRecvMsgSize(2*config.StreamSize), grpc.MaxSendMsgSize(2*config.StreamSize))

	mixnet.RegisterMixServer(grpcServer, mixer)
	server.RegisterXRDServer(grpcServer, serv)

	lis, err := net.Listen("tcp", config.Port(*addr))
	if err != nil {
		log.Fatal("Could not listen:", addr, err)
	}

	go func() {
		err = grpcServer.Serve(lis)
		if err != nil && err != grpc.ErrServerStopped {
			log.Fatal("Serve err:", err)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	grpcServer.Stop()
}
