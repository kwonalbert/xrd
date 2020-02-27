package verifiable_mixnet

import (
	"encoding/binary"
	"io"
)

type Shuffler struct {
	perm []int
	rand io.Reader
}

// generate a shuffler that randomly shuffles an array
// using rand as the source of randomness
func NewShuffler(rand io.Reader) *Shuffler {
	return &Shuffler{
		perm: nil,
		rand: rand,
	}
}

// shuffle array in in-place
func (sr *Shuffler) Shuffle(in [][]byte) {
	orig := make([][]byte, len(in))
	copy(orig, in)
	var p []int
	if sr.perm == nil || len(sr.perm) != len(in) {
		sr.perm = sr.permutation(len(in))
	}
	p = sr.perm

	for i := 0; i < len(in); i++ {
		in[i] = orig[p[i]]
	}
}

// generate a random permutation of n elements
func (sr *Shuffler) permutation(n int) []int {
	arr := make([]int, n)
	for i := 0; i < n; i++ {
		arr[i] = i
	}

	for i := n - 1; i >= 0; i-- {
		j := sr.randInt(i + 1)
		arr[i], arr[j] = arr[j], arr[i]
	}

	return arr
}

// generate a random integer < mod
func (sr *Shuffler) randInt(mod int) int {
	tmp := make([]byte, 4)
	n, err := sr.rand.Read(tmp)
	if err != nil || n < 4 {
		panic("Could not read random bytes")
	}
	val := int(binary.BigEndian.Uint32(tmp))
	return val % mod
}
