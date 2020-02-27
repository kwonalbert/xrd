package mixnet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"sync"
)

type Client interface {
	// NewRound sets the public key for a particular round.
	NewRound(round int, publicXs, publicYs []*big.Int)
	// EndRound deletes the round state.
	EndRound(round int) error

	// GenerateRoundInput encrypts the plaintext, and returns
	// the inner ciphertext and the corresponding shares.
	GenerateRoundInput(round int, plaintext []byte) []byte
}

type client struct {
	smu    sync.RWMutex
	states map[int]*clientRoundState
}

type clientRoundState struct {
	round    int
	publicXs []*big.Int
	publicYs []*big.Int
	X        *big.Int
	Y        *big.Int
}

func NewClient() Client {
	return &client{
		states: make(map[int]*clientRoundState),
	}
}

func (clt *client) NewRound(round int, publicXs, publicYs []*big.Int) {
	clt.smu.Lock()
	x, y := big.NewInt(0), big.NewInt(0)
	for i := range publicXs {
		x, y = curve.Add(x, y, publicXs[i], publicYs[i])
	}

	clt.states[round] = &clientRoundState{
		round:    round,
		publicXs: publicXs,
		publicYs: publicYs,
		X:        x,
		Y:        y,
	}
	clt.smu.Unlock()
}

func (clt *client) EndRound(round int) error {
	clt.smu.Lock()
	defer clt.smu.Unlock()
	_, ok := clt.states[round]
	if !ok {
		return errors.New("Trying to delete a non-existing round")
	}
	delete(clt.states, round)
	return nil
}

func (clt *client) GenerateRoundInput(round int, plaintext []byte) []byte {
	clt.smu.RLock()
	state := clt.states[round]
	clt.smu.RUnlock()

	var nonce [24]byte
	binary.PutUvarint(nonce[:], uint64(round))

	rx, ry, ciphertext := Encrypt(state.X, state.Y, &nonce, plaintext)
	buf := new(bytes.Buffer)

	// sometimes, big ints are encoded as < 32 bytes..
	xb := rx.Bytes()
	for i := 0; i < 32-len(xb); i++ {
		buf.WriteByte(0)
	}
	buf.Write(xb)
	yb := ry.Bytes()
	for i := 0; i < 32-len(yb); i++ {
		buf.WriteByte(0)
	}
	buf.Write(yb)
	buf.Write(ciphertext)

	return buf.Bytes()
}
