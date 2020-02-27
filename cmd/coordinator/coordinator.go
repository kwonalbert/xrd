package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/kwonalbert/xrd/config"
	"github.com/kwonalbert/xrd/coordinator"
)

var (
	serverFile  = flag.String("servers", "server.config", "Server configuration file name")
	groupFile   = flag.String("groups", "group.config", "Group configuration file name")
	mailboxFile = flag.String("mailboxes", "mailbox.config", "Mailbox configuration file name")
	clientFile  = flag.String("clients", "client.config", "Client configuration file name")
)

func printHelp() {
	fmt.Println("new <round_number> <num_users>: start a new round")
	fmt.Println("generate <msg_size>: generate messages for submission")
	fmt.Println("submit: submit generated messages")
	fmt.Println("start: start the experiment")
}

func readLine(reader *bufio.Reader) string {
	text, _ := reader.ReadString('\n')
	text = strings.Replace(text, "\n", "", -1)
	return text
}

func readUint64(reader *bufio.Reader) uint64 {
	for {
		line := readLine(reader)
		res, err := strconv.Atoi(line)
		if err != nil {
			fmt.Println("Incorrect input")
			continue
		}
		return uint64(res)
	}
}

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

	coordinator := coordinator.NewCoordinator(mcfgs, ccfgs, scfgs, gcfgs)

	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Quark experiment coordinator")

	printHelp()

	round := 0
	for {
		fmt.Print("--$ ")
		line := readLine(reader)

		if strings.Compare("new", line) == 0 || strings.Compare("n", line) == 0 {
			fmt.Println("Round number: ")
			round = int(readUint64(reader))
			fmt.Println("Number of users: ")
			numUsers := int(readUint64(reader))
			err := coordinator.NewRound(round, numUsers)
			if err != nil {
				fmt.Println("NewRound error:", err)
			}
		} else if strings.Compare("generate", line) == 0 || strings.Compare("g", line) == 0 {
			fmt.Print("Message size: ")
			msgSize := int(readUint64(reader))
			err := coordinator.GenerateMessages(round, msgSize)
			if err != nil {
				fmt.Println("Generate error: ", err)
			}
		} else if strings.Compare("submit", line) == 0 || strings.Compare("b", line) == 0 {
			err := coordinator.SubmitMessages(round)
			if err != nil {
				fmt.Println("Submit error: ", err)
			}
		} else if strings.Compare("start", line) == 0 || strings.Compare("s", line) == 0 {
			err := coordinator.StartExperiment(round)
			if err != nil {
				fmt.Println("Start error: ", err)
			} else {
				round = -1 // reset the round to ensure no bad usage
			}
		} else if strings.Compare("quit", line) == 0 {
			break
		} else {
			fmt.Println("Unrecognized command")
		}
	}
}
