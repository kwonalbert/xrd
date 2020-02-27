package verifiable_mixnet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/box"
)

const Overhead = sha256.Size
const SymmetricKeySize = 16

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

func Seal(out, message []byte, nonce *[24]byte, peersPublicKey, privateKey *[32]byte) []byte {
	var sharedKey [32]byte
	box.Precompute(&sharedKey, peersPublicKey, privateKey)
	return SecretSeal(out, message, nonce, &sharedKey)
}

func Open(out, abox []byte, nonce *[24]byte, peersPublicKey, privateKey *[32]byte) ([]byte, bool) {
	var sharedKey [32]byte
	box.Precompute(&sharedKey, peersPublicKey, privateKey)
	return SecretOpen(out, abox, nonce, &sharedKey)
}

// SecretSeal performs AES-HMAC authenticated encryption with a
// symmetric key. TODO: We need to check that out does not overlap
// the message or the nonce.
func SecretSeal(out, message []byte, nonce *[24]byte, key *[32]byte) []byte {
	keys := hkdf.New(sha256.New, (*key)[:], (*nonce)[:], nil)
	aesKey := make([]byte, SymmetricKeySize)
	hmacKey := make([]byte, SymmetricKeySize)

	n, err := keys.Read(aesKey)
	if err != nil {
		panic("Could not generate aes key")
	} else if n != len(aesKey) {
		panic("Could not read enough bytes for aes key")
	}

	n, err = keys.Read(hmacKey)
	if err != nil {
		panic("Could not generate hmac key")
	} else if n != len(hmacKey) {
		panic("Could not read enough bytes for hmac key")
	}

	ret, out := sliceForAppend(out, len(message)+Overhead)

	iv := (*nonce)[:aes.BlockSize]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic("Could not create new aes cipher")
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(out[:len(out)-Overhead], message)

	hmac.New(sha256.New, hmacKey).Sum(out[:len(out)-Overhead])
	return ret
}


// SecretOpen opens the ciphertext generated using SecretSeal.
func SecretOpen(out, box []byte, nonce *[24]byte, key *[32]byte) ([]byte, bool) {	
	keys := hkdf.New(sha256.New, (*key)[:], (*nonce)[:], nil)
	aesKey := make([]byte, SymmetricKeySize)
	hmacKey := make([]byte, SymmetricKeySize)

	n, err := keys.Read(aesKey)
	if err != nil {
		panic("Could not generate aes key")
	} else if n != len(aesKey) {
		panic("Could not read enough bytes for aes key")
	}

	n, err = keys.Read(hmacKey)
	if err != nil {
		panic("Could not generate hmac key")
	} else if n != len(hmacKey) {
		panic("Could not read enough bytes for hmac key")
	}

	mac := hmac.New(sha256.New, hmacKey)
	var orig [Overhead]byte
	copy(orig[:], box[len(box)-Overhead:])
	mac.Sum(box[:len(box)-Overhead])
	if !hmac.Equal(box[len(box)-Overhead:], orig[:]) {
		return nil, false
	}

	ret, out := sliceForAppend(out, len(box)-Overhead)

	iv := (*nonce)[:aes.BlockSize]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic("Could not create new aes cipher")
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(out, box[:len(box)-Overhead])

	return ret, true
}
