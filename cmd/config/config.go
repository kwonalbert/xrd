package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/kwonalbert/xrd/config"
)

var (
	ipList      = flag.String("ips", "ip.list", "list of server ips")
	f           = flag.Float64("f", 0.2, "Fraction of malicious servers")
	serverFile  = flag.String("servers", "server.config", "Server configuration file name")
	groupFile   = flag.String("groups", "group.config", "Group configuration file name")
	mailboxFile = flag.String("mailboxes", "mailbox.config", "Mailbox configuration file name")
	clientFile  = flag.String("clients", "client.config", "Client configuration file name")
)

func main() {
	flag.Parse()

	ifile, err := os.Open(*ipList)
	if err != nil {
		log.Fatal("Could not open the ip")
	}
	reader := csv.NewReader(ifile)
	ips, err := reader.ReadAll()
	if err != nil {
		log.Fatal("Could not read the list of ips")
	}
	ifile.Close()
	var servers []string
	var mailboxes []string
	var clients []string

	for _, ip := range ips {
		if ip[0] == "server" {
			servers = append(servers, ip[1])
		} else if ip[0] == "mailbox" {
			mailboxes = append(mailboxes, ip[1])
		} else if ip[0] == "client" {
			clients = append(clients, ip[1])
		}
	}

	scfgs, gcfgs := config.CreateGroupConfig(len(servers), *f, servers)
	//scfgs, gcfgs := config.CreateOneGroupConfig(servers)

	ccfgs := make(map[string]*config.Server)
	for c := range clients {
		cid := fmt.Sprintf("client:%d", c)
		ccfgs[cid] = config.CreateServerWithExisting(clients[c], cid, ccfgs)
	}

	mcfgs := make(map[string]*config.Server)
	for m := range mailboxes {
		mid := fmt.Sprintf("mailbox:%d", m)
		mcfgs[mid] = config.CreateServerWithExisting(mailboxes[m], mid, mcfgs)
	}

	err = config.MarshalServersToFile(*serverFile, scfgs)
	if err != nil {
		log.Fatal(err)
	}
	err = config.MarshalGroupsToFile(*groupFile, gcfgs)
	if err != nil {
		log.Fatal(err)
	}
	err = config.MarshalServersToFile(*mailboxFile, mcfgs)
	if err != nil {
		log.Fatal(err)
	}
	err = config.MarshalServersToFile(*clientFile, ccfgs)
	if err != nil {
		log.Fatal(err)
	}
}
