package config

import (
	"fmt"
	"testing"
)

func createServers(n int) map[string]*Server {
	servers := make(map[string]*Server)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("servers:%d", i)
		server := CreateServer("localhost", id)
		servers[id] = server
	}
	return servers
}

func createGroups(n int) map[string]*Group {
	groups := make(map[string]*Group)
	for i := 0; i < n; i++ {
		gid := fmt.Sprintf("group:%d", i)
		group := &Group{
			Gid:     gid,
			Layer:   0,
			Row:     uint32(i),
			Servers: nil,
		}
		groups[gid] = group
	}
	return groups
}

func isDisjoint(a1, a2 []*Group) bool {
	for a := range a1 {
		for b := range a2 {
			if a == b {
				return false
			}
		}
	}
	return true
}

func TestAssignments(t *testing.T) {
	n := 40
	groups := createGroups(n)
	assigns := Assignments(groups)

	for _, assign1 := range assigns {
		for _, assign2 := range assigns {
			if isDisjoint(assign1, assign2) {
				t.Error("Not connected")
			}
		}
	}

	counts := make(map[*Group]int)
	for _, group := range groups {
		counts[group] = 0
	}

	for _, assign := range assigns {
		for _, group := range assign {
			counts[group] += 1
		}
	}
	for _, count := range counts {
		if count > 3 {
			t.Error("More than 3 groups connected to a chain")
		}
		if count < 2 {
			t.Error("Under utilizing chains")
		}
	}
}
