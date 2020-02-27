package mixnet

import (
	"encoding/binary"
	"errors"
	"log"
	"math/big"
	"runtime"
	"sync"
)

type Verifier interface {
	NewRound(round int) error

	EndRound(round int) error

	SetPublicKey(round int, x, y *big.Int) error

	PublicKey(round int) (*big.Int, *big.Int, error)

	PrivateKey(round int) (*big.Int, error)

	AddInnerCiphertexts(round int, msgs [][]byte) error

	Finalize(round int, privateKeys [][]byte) ([][]byte, error)
}

type verifier struct {
	round int

	index     int
	groupSize int

	smu    sync.RWMutex
	states map[int]*verifierRoundState
}

// internal per round state for verifier
type verifierRoundState struct {
	sync.Mutex
	round int

	// private and public keys of this round
	private *big.Int
	publicX *big.Int
	publicY *big.Int

	innerCiphertexts [][]byte

	decJobs chan decryptionJob
	done    bool
}

func NewVerifier(index int, groupSize int) Verifier {
	v := &verifier{
		round: 0,

		index:     index,
		groupSize: groupSize,

		states: make(map[int]*verifierRoundState),
	}
	return v
}

func (ver *verifier) NewRound(round int) error {
	if round < ver.round {
		return errors.New("Cannot start previous rounds")
	}
	ver.smu.Lock()
	defer ver.smu.Unlock()
	if _, ok := ver.states[round]; ok {
		return errors.New("Round already started.")
	}

	ver.round = round // keep track of the lastest round number
	priv, px, py := GenerateInnerKey()
	state := &verifierRoundState{
		round:   round,
		private: priv,
		publicX: px,
		publicY: py,

		innerCiphertexts: nil,

		decJobs: make(chan decryptionJob, runtime.NumCPU()*16),

		done: false,
	}
	for i := 0; i < runtime.NumCPU()*2; i++ {
		go decryptionWorker(round, state.decJobs)
	}
	ver.states[round] = state

	return nil
}

func (ver *verifier) EndRound(round int) error {
	if round > ver.round {
		return errors.New("Cannot delete future rounds")
	}
	ver.smu.RLock()
	state, ok := ver.states[round]
	ver.smu.RUnlock()
	if !ok {
		return errors.New("Round already deleted")
	}

	state.Lock()
	defer state.Unlock()
	if !state.done {
		log.Println("Couldn't delete", ver.index)
		return errors.New("Cannot delete a round that has not finished")
	}
	close(state.decJobs)

	ver.smu.Lock()
	delete(ver.states, round)
	ver.smu.Unlock()
	return nil
}

func (ver *verifier) SetPublicKey(round int, x, y *big.Int) error {
	ver.smu.RLock()
	state, ok := ver.states[round]
	ver.smu.RUnlock()
	if !ok {
		return errors.New("Looking for non-existing keys")
	}

	state.Lock()
	state.publicX = x
	state.publicY = y
	state.Unlock()

	return nil
}

func (ver *verifier) PublicKey(round int) (*big.Int, *big.Int, error) {
	ver.smu.RLock()
	state, ok := ver.states[round]
	ver.smu.RUnlock()
	if !ok {
		return nil, nil, errors.New("Looking for non-existing keys")
	}
	return state.publicX, state.publicY, nil
}

type decryptionJob struct {
	privateKey *big.Int
	ciphertext []byte
	idx        int
	errs       []error
	results    [][]byte
	wg         *sync.WaitGroup
}

func decryptionWorker(round int, jobs chan decryptionJob) {
	var nonce [24]byte
	binary.PutUvarint(nonce[:], uint64(round))
	x, y := new(big.Int), new(big.Int)

	for job := range jobs {
		ciphertext := job.ciphertext
		xb, yb := ciphertext[:32], ciphertext[32:64]
		msg := ciphertext[64:]
		rx, ry := x.SetBytes(xb), y.SetBytes(yb)
		plaintext, err := Decrypt(job.privateKey, &nonce, rx, ry, msg)
		job.results[job.idx] = plaintext
		job.errs[job.idx] = err
		job.wg.Done()
	}
}

func (ver *verifier) PrivateKey(round int) (*big.Int, error) {
	ver.smu.RLock()
	state, ok := ver.states[round]
	ver.smu.RUnlock()
	if !ok {
		return nil, errors.New("Round not yet started")
	}

	return state.private, nil
}

func (ver *verifier) AddInnerCiphertexts(round int, inners [][]byte) error {
	ver.smu.RLock()
	state, ok := ver.states[round]
	ver.smu.RUnlock()
	if !ok {
		return errors.New("Round not yet started")
	}

	state.innerCiphertexts = inners

	return nil
}

func (ver *verifier) Finalize(round int, privateKeys [][]byte) ([][]byte, error) {
	ver.smu.RLock()
	state, ok := ver.states[round]
	ver.smu.RUnlock()
	if !ok {
		return nil, errors.New("Round not yet started")
	}

	if state.innerCiphertexts == nil {
		return nil, errors.New("Cannot finalize without inner ciphertexts")
	}

	aggKey := big.NewInt(0)
	for _, priv := range privateKeys {
		aggKey = aggKey.Add(aggKey, new(big.Int).SetBytes(priv))
	}

	wg := new(sync.WaitGroup)
	wg.Add(len(state.innerCiphertexts))
	errs := make([]error, len(state.innerCiphertexts))
	plaintexts := make([][]byte, len(state.innerCiphertexts))

	for c := range state.innerCiphertexts {
		state.decJobs <- decryptionJob{
			privateKey: aggKey,
			ciphertext: state.innerCiphertexts[c],
			idx:        c,
			errs:       errs,
			results:    plaintexts,
			wg:         wg,
		}
	}

	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}

	state.Lock()
	state.done = true
	state.Unlock()

	return plaintexts, nil
}
