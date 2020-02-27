package config

import (
	"fmt"
	"log"
	"sort"
	"testing"
)

func TestCreateGroupConfig(t *testing.T) {
	N := 100 // number of groups
	n := 100 // number of servers
	f := 0.2
	baseAddr := "localhost:%d"

	addrs := make([]string, n)
	for i := range addrs {
		addrs[i] = fmt.Sprintf(baseAddr, i)
	}

	servers, groups := CreateGroupConfig(N, f, addrs)

	size := GroupSize(N, f)

	counts := make(map[string]int)
	overlapCount := make(map[string][]int)
	for _, addr := range addrs {
		counts[addr] = 0
		overlapCount[addr] = make([]int, size)
		for i := range overlapCount[addr] {
			overlapCount[addr][i] = 0
		}
	}

	for _, group := range groups {
		for i, id := range group.Servers {
			addr := servers[id].Address
			counts[addr] += 1
			overlapCount[addr][i] += 1
		}
	}

	slist := make([]string, n)
	i := 0
	for id := range counts {
		slist[i] = id
		i++
	}
	sort.Strings(slist)

	sum := 0
	max := -1

	overlapMax := -1
	for i := range slist {
		count := counts[slist[i]]
		sum += count
		if max < count {
			max = count
		}

		overlaps := overlapCount[slist[i]]
		for _, overlap := range overlaps {
			if overlapMax < overlap {
				overlapMax = overlap
			}
		}
	}

	// for addr := range overlapCount {
	// 	fmt.Println(addr, overlapCount[addr])
	// }

	log.Println("Group size:", size)
	log.Println("Average count:", float64(sum)/float64(len(slist)))
	log.Println("Max count:", max)
	log.Println("Max overlap:", overlapMax)
}

func TestCreateOneGroupConfig(t *testing.T) {
	n := 31 // number of servers
	baseAddr := "localhost:%d"

	addrs := make([]string, n)
	for i := range addrs {
		addrs[i] = fmt.Sprintf(baseAddr, i)
	}

	CreateOneGroupConfig(addrs)
}
