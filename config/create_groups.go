package config

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"
	"sort"

	"golang.org/x/crypto/sha3"
)

// just some random bytes. picking a seed in advance to repeat
// experiments deterministically
var seed = []byte{
	196, 90, 111, 1, 181, 197, 66, 167, 74, 39, 198, 144, 4, 179, 62, 115,
	192, 144, 122, 196, 242, 225, 81, 118, 131, 206, 191, 12, 210, 221, 64, 192,
	161, 225, 17, 161, 202, 156, 90, 143, 55, 195, 143, 187, 143, 252, 7, 6,
	0, 245, 9, 16, 3, 192, 43, 236, 164, 230, 24, 1, 174, 71, 189, 252,
	216, 146, 139, 105, 3, 0, 70, 9, 102, 179, 127, 147, 154, 104, 11, 155,
	63, 133, 121, 66, 142, 141, 23, 240, 81, 53, 166, 154, 39, 105, 179, 45,
}

type RandReader struct {
	io.Reader
}

func NewRandReader(seed []byte) *RandReader {
	h := sha3.NewShake128()
	h.Write(seed)
	return &RandReader{h}
}

func (r *RandReader) UInt64() uint64 {
	buf := make([]byte, 8)
	_, err := r.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	tmp := binary.BigEndian.Uint64(buf)
	return tmp
}

// Knuth shuffle
func (r *RandReader) Perm(n int) []int {
	pi := make([]int, n)
	for i := 0; i < n; i++ {
		pi[i] = i
	}
	for i := 0; i <= n-2; i++ {
		j := int(r.UInt64() % uint64(n-i))
		j += i
		pi[i], pi[j] = pi[j], pi[i]
	}
	return pi
}

// select t out of n, without replacement
func (r *RandReader) SelectRandom(n int, t int) []int {
	return r.Perm(n)[:t]
}

func GroupSize(nGroups int, f float64) int {
	target := math.Exp2(float64(-64)) / float64(nGroups)
	size := math.Ceil(math.Log2(target) / math.Log2(f))
	return int(size)
}

func findPosition(counts []int, current []string) int {
	// counts of each item, infinity if spot is taken
	emptyCounts := make([]int, len(current))
	for i := range current {
		if current[i] == "" {
			emptyCounts[i] = counts[i]
		} else {
			emptyCounts[i] = 1 << 48
		}
	}

	min := emptyCounts[0]
	minIdx := 0
	for i, v := range emptyCounts {
		if v < min {
			min = v
			minIdx = i
		}
	}
	return minIdx
}

func full(group []string) bool {
	for i := range group {
		if group[i] == "" {
			return false
		}
	}
	return true
}

// a heuristic to stagger the groups
func staggerGroups(addrs []string, groups [][]string) [][]string {
	counts := make(map[string][]int)
	for _, addr := range addrs {
		counts[addr] = make([]int, len(groups[0]))
		for i := range counts[addr] {
			counts[addr][i] = 0
		}
	}

	staggered := make([][]string, len(groups))
	for i := range groups {
		staggered[i] = make([]string, len(groups[i]))
		for j := range staggered[i] {
			staggered[i][j] = ""
		}

		for _, server := range groups[i] {
			idx := findPosition(counts[server], staggered[i])
			// if counts[server][idx] != 0 && !full(groups[i]) {
			// 	staggered[i][idx] = "FILLED"
			// 	newIdx := findPosition(counts[server], staggered[i])
			// 	staggered[i][newIdx] = server
			// 	counts[server][newIdx]++
			// 	staggered[i][idx] = ""
			// } else {
			staggered[i][idx] = server
			counts[server][idx]++
			//}
		}
	}
	return staggered
}

func CreateRandomGroupsWithSize(nGroups, size int, addrs []string) [][]string {
	n := len(addrs)
	groups := make([][]string, nGroups)
	r := NewRandReader(seed)
	for g := range groups {
		groups[g] = make([]string, size)
		indices := r.SelectRandom(n, size)
		sort.Ints(indices)
		shift := g % size
		indices = append(indices[shift:], indices[:shift]...)
		for i := range groups[g] {
			groups[g][i] = addrs[indices[i]]
		}
	}
	return groups
}

func CreateRandomGroups(nGroups int, f float64, addrs []string) [][]string {
	n := len(addrs)
	size := GroupSize(nGroups, f)
	if size > n { // this should never happen in practice, but useful for testing..
		size = n
	}

	groups := CreateRandomGroupsWithSize(nGroups, size, addrs)

	return staggerGroups(addrs, groups)
}

func CreateGroupsWithAddresses(addrs [][]string) (map[string]*Server, map[string]*Group) {
	servers := make(map[string]*Server)
	groups := make(map[string]*Group)

	for g := 0; g < len(addrs); g++ {
		gid := fmt.Sprintf("group:%d", g)
		group := &Group{
			Gid:     gid,
			Layer:   0,
			Row:     uint32(g),
			Servers: make([]string, len(addrs[g])),
		}

		for i := 0; i < len(addrs[g]); i++ {
			id := fmt.Sprintf("server:(%d,%d)", g, i)
			server := CreateServerWithExisting(addrs[g][i], id, servers)
			servers[id] = server
			group.Servers[i] = id
		}
		groups[gid] = group
	}

	return servers, groups
}

func CreateGroupConfig(nGroups int, f float64, addrs []string) (map[string]*Server, map[string]*Group) {
	return CreateGroupsWithAddresses(CreateRandomGroups(nGroups, f, addrs))
}

func CreateOneGroupConfig(addrs []string) (map[string]*Server, map[string]*Group) {
	return CreateGroupsWithAddresses([][]string{addrs})
}
