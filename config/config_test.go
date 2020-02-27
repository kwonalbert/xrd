package config

import (
	"bytes"
	"fmt"
	"testing"
)

func TestGroups(t *testing.T) {
	nServers := 5
	addrs := make([]string, nServers)
	for i := 0; i < nServers; i++ {
		addrs[i] = fmt.Sprintf("localhost:%d", 8000+i)
	}
}

func TestMarshaling(t *testing.T) {
	servers := createServers(5)

	buf := new(bytes.Buffer)
	err := MarshalServers(buf, servers)
	if err != nil {
		t.Fatal(err)
	}

	sres, err := UnmarshalServers(buf)
	if err != nil {
		t.Fatal(err)
	}

	for res := range sres {
		found := false
		for exp := range servers {
			if exp == res {
				found = true
				break
			}
		}
		if !found {
			t.Fatal(err)
		}
	}

	groups := createGroups(5)

	err = MarshalGroups(buf, groups)
	if err != nil {
		t.Fatal(err)
	}

	gres, err := UnmarshalGroups(buf)
	if err != nil {
		t.Fatal(err)
	}

	for res := range gres {
		found := false
		for exp := range groups {
			if exp == res {
				found = true
				break
			}
		}
		if !found {
			t.Fatal(err)
		}
	}

}
