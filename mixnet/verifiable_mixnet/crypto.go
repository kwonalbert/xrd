package verifiable_mixnet

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"log"
	"math/big"
	"sync"

	"golang.org/x/crypto/nacl/box"
)

const BOX_KEY_SIZE = 32
const SHARED_KEY_SIZE = 32
const NONCE_SIZE = 24

var zeros [16]byte

var zeros64 [64]byte

var curve = elliptic.P256()
var order = curve.Params().N

const POINT_SIZE = 64

type point struct {
	x *big.Int
	y *big.Int
}

func reverse(arr [][]byte) {
	for i := 0; i < len(arr)/2; i++ {
		arr[i], arr[len(arr)-1-i] = arr[len(arr)-1-i], arr[i]
	}
}

func Nonce(round, row, index int) [NONCE_SIZE]byte {
	var nonce [NONCE_SIZE]byte
	binary.PutUvarint(nonce[:8], uint64(round))
	binary.PutUvarint(nonce[8:16], uint64(row))
	binary.PutUvarint(nonce[16:], uint64(index))
	return nonce
}

func defaultDecryptionWorker(nonce *[NONCE_SIZE]byte, auxSize int, wg *sync.WaitGroup, jobs chan DecryptionJob) {
	var theirKey [BOX_KEY_SIZE]byte
	for job := range jobs {
		copy(theirKey[:], job.ciphertext[:BOX_KEY_SIZE])

		res, ok := Open(nil, job.ciphertext[BOX_KEY_SIZE+auxSize:], nonce, &theirKey, job.privateKey)
		if !ok {
			job.result[job.idx] = nil
			log.Println("open failed")
			wg.Done()
			continue
		}

		var na []byte = nil
		if job.auxProcessor != nil {
			ok, na = job.auxProcessor(job.ciphertext, res, auxSize)
			if !ok {
				job.result[job.idx] = nil
				log.Println("auxprocessor failed")
				wg.Done()
				continue
			}
		}

		if na != nil {
			res = append(na, res...)
		}
		job.result[job.idx] = res
		wg.Done()
	}
}

// encrypt just one layer
func Encrypt(msg []byte, aux []byte, nonce *[NONCE_SIZE]byte, key *[BOX_KEY_SIZE]byte) []byte {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	res := make([]byte, len(msg)+len(aux)+BOX_KEY_SIZE+Overhead)

	Seal(res[BOX_KEY_SIZE+len(aux):BOX_KEY_SIZE+len(aux)],
		msg, nonce, key, privateKey)

	copy(res[:], (*publicKey)[:])
	copy(res[BOX_KEY_SIZE:], aux)

	return res
}

// auxs is auxilary data to append to the ith layer of encryption.
// keys given should be in reverse encryption order
// (i.e., message traversal order).
// auxs and keys are reversed in place, so the caller should
// not reuse these arrays outside
func OnionEncrypt(msg []byte, auxs [][]byte, nonces [][]byte, keys [][]byte) []byte {
	reverse(auxs)
	reverse(nonces)
	reverse(keys)

	var theirKey [BOX_KEY_SIZE]byte
	var nonce [NONCE_SIZE]byte

	totalSize := len(msg)
	for i := range auxs {
		totalSize += len(auxs[i])
		totalSize += BOX_KEY_SIZE + Overhead
	}

	// avoid allocation by creating arrays ahead of time
	res := make([]byte, totalSize)
	in := make([]byte, totalSize)

	copy(in[:], msg)
	l := len(msg)
	for i := range keys {
		publicKey, privateKey, err := box.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		copy(theirKey[:], keys[i])
		copy(nonce[:], nonces[i])

		Seal(res[BOX_KEY_SIZE+len(auxs[i]):BOX_KEY_SIZE+len(auxs[i])], in[:l], &nonce, &theirKey, privateKey)

		copy(res[:], (*publicKey)[:])
		copy(res[BOX_KEY_SIZE:], auxs[i])

		l = l + BOX_KEY_SIZE + len(auxs[i]) + Overhead
		copy(in, res[:l])
	}
	return res
}

func GenerateP256Key() (*big.Int, *big.Int, *big.Int) {
	priv, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		panic(err)
	}
	pb := priv.Bytes()
	x, y := curve.ScalarBaseMult(pb)
	return x, y, priv
}

func GenerateP256KeyWithBase(basex, basey *big.Int) (*big.Int, *big.Int, *big.Int) {
	priv, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		panic(err)
	}
	pb := priv.Bytes()
	x, y := curve.ScalarMult(basex, basey, pb)
	return x, y, priv
}

func P256KeyToBytes(x, y, priv *big.Int) ([]byte, []byte) {
	pub := make([]byte, POINT_SIZE)
	xb := x.Bytes()
	yb := y.Bytes()
	copy(pub[POINT_SIZE/2-len(xb):], xb)
	copy(pub[POINT_SIZE-len(yb):], yb)

	pb := priv.Bytes()
	secret := make([]byte, 32)
	copy(secret[32-len(pb):], pb)

	return pub, secret
}

func P256DecryptionWorker(nonce *[NONCE_SIZE]byte, auxSize int, wg *sync.WaitGroup, jobs chan DecryptionJob) {
	theirKeyX, theirKeyY := new(big.Int), new(big.Int)
	var sharedKey [SHARED_KEY_SIZE]byte
	for job := range jobs {
		theirKeyX.SetBytes(job.ciphertext[:POINT_SIZE/2])
		theirKeyY.SetBytes(job.ciphertext[POINT_SIZE/2 : POINT_SIZE])
		sharedX, _ := curve.ScalarMult(theirKeyX, theirKeyY, (*job.privateKey)[:])
		sxb := sharedX.Bytes()
		// explicitly zero out the rest, since we are reusing arrays
		copy(sharedKey[SHARED_KEY_SIZE-len(sxb):], sxb)
		for b := 0; b < SHARED_KEY_SIZE-len(sxb); b++ {
			sharedKey[b] = 0
		}

		blindX, blindY := curve.ScalarMult(theirKeyX, theirKeyY, job.privateBlindKey)

		bxb, byb := blindX.Bytes(), blindY.Bytes()
		res := make([]byte, POINT_SIZE,
			len(job.ciphertext)-Overhead-auxSize)
		copy(res[POINT_SIZE/2-len(bxb):], bxb)
		copy(res[POINT_SIZE-len(byb):], byb)

		if job.prodJob != nil {
			job.prodWg.Add(1)
			job.prodJob <- res[:POINT_SIZE]
		}

		// append to res
		res, ok := SecretOpen(res, job.ciphertext[POINT_SIZE+auxSize:],
			nonce, &sharedKey)
		if !ok {
			job.result[job.idx] = nil
			log.Println("open failed")
			wg.Done()
			continue
		}

		job.result[job.idx] = res
		wg.Done()
	}
}

func P256OnionEncrypt(msg []byte, auxs [][]byte, nonces [][]byte, keys [][]byte, nizk bool) ([]byte, []byte) {
	reverse(auxs)
	reverse(nonces)
	reverse(keys)

	theirKeyX, theirKeyY := new(big.Int), new(big.Int)
	var nonce [NONCE_SIZE]byte

	totalSize := len(msg) + POINT_SIZE // POINT_SIZE for the diffie-hellman key
	for i := range auxs {
		totalSize += len(auxs[i])
		totalSize += Overhead
	}

	// avoid allocation by creating arrays ahead of time
	res := make([]byte, totalSize)
	in := make([]byte, totalSize)

	copy(in[:], msg)
	l := len(msg)

	privateKey, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		panic(err)
	}
	publicX, publicY := curve.ScalarBaseMult(privateKey.Bytes())

	var sharedKey [SHARED_KEY_SIZE]byte
	pb := privateKey.Bytes()

	for i := range keys {
		theirKeyX.SetBytes(keys[i][:POINT_SIZE/2])
		theirKeyY.SetBytes(keys[i][POINT_SIZE/2 : POINT_SIZE])
		copy(nonce[:], nonces[i])

		sharedX, _ := curve.ScalarMult(theirKeyX, theirKeyY, pb)
		sxb := sharedX.Bytes()
		copy(sharedKey[SHARED_KEY_SIZE-len(sxb):], sxb)
		// explicitly zero out the rest, since we are reusing arrays
		for b := 0; b < SHARED_KEY_SIZE-len(sxb); b++ {
			sharedKey[b] = 0
		}

		// POINT_SIZE bytes reserved for the public keys
		SecretSeal(res[len(auxs[i])+POINT_SIZE:len(auxs[i])+POINT_SIZE], in[:l], &nonce, &sharedKey)

		copy(res[POINT_SIZE:], auxs[i])

		l = l + len(auxs[i]) + Overhead
		copy(in, res[POINT_SIZE:POINT_SIZE+l])
	}

	// some values are less than POINT_SIZE/2 bytes
	xb := publicX.Bytes()
	yb := publicY.Bytes()
	copy(res[POINT_SIZE/2-len(xb):], xb)
	copy(res[POINT_SIZE-len(yb):], yb)

	// rereverse the arrays so it remains the same as before
	reverse(auxs)
	reverse(nonces)
	reverse(keys)
	if nizk {
		return res, PoKLog(privateKey, publicX, publicY)
	} else {
		return res, nil
	}
}
