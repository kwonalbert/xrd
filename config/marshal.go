package config

import (
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/gogo/protobuf/proto"
)

func MarshalServers(writer io.Writer, servers map[string]*Server) error {
	sp := &Servers{
		Servers: servers,
	}

	return proto.MarshalText(writer, sp)
}

func MarshalServersToFile(fn string, servers map[string]*Server) error {
	file, err := os.Create(fn)
	if err != nil {
		log.Fatal("Could not create file")
	}
	return MarshalServers(file, servers)
}

func UnmarshalServers(reader io.Reader) (map[string]*Server, error) {
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	text := string(b)

	sp := &Servers{}
	err = proto.UnmarshalText(text, sp)

	return sp.Servers, err
}

func UnmarshalServersFromFile(fn string) (map[string]*Server, error) {
	file, err := os.Open(fn)
	if err != nil {
		log.Fatal("Could not open group file")
	}
	return UnmarshalServers(file)
}

func MarshalGroups(writer io.Writer, groups map[string]*Group) error {
	sp := &Groups{
		Groups: groups,
	}

	return proto.MarshalText(writer, sp)
}

func MarshalGroupsToFile(fn string, groups map[string]*Group) error {
	file, err := os.Create(fn)
	if err != nil {
		log.Fatal("Could not create file")
	}
	return MarshalGroups(file, groups)
}

func UnmarshalGroups(reader io.Reader) (map[string]*Group, error) {
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	text := string(b)

	sp := &Groups{}
	err = proto.UnmarshalText(text, sp)

	return sp.Groups, err
}

func UnmarshalGroupsFromFile(fn string) (map[string]*Group, error) {
	file, err := os.Open(fn)
	if err != nil {
		log.Fatal("Could not open group file")
	}
	return UnmarshalGroups(file)
}
