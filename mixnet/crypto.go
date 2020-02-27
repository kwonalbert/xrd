package mixnet

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/sha3"
)

var curve = elliptic.P256()
var curveParams = curve.Params()
var order = curveParams.N

// overhead of oninon enryption is (x,y) coordinates + sercretbox overhead
const Overhead = 32 + 32 + secretbox.Overhead

func GenerateInnerKey() (*big.Int, *big.Int, *big.Int) {
	priv, err := rand.Int(rand.Reader, order)
	if err != nil {
		panic("Could not generate a private key")
	}
	px, py := curve.ScalarBaseMult(priv.Bytes())
	return priv, px, py
}

// Encrypt returns a triplet, which is a ciphertext encrypted under
// the trustees public key (publicX, publicY) using the key
// encapsulation technique. The ciphertext consists of randomness
// used to established the shared key and the encrypted plaintext.
func Encrypt(publicX, publicY *big.Int, nonce *[24]byte, plaintext []byte) (*big.Int, *big.Int, []byte) {
	priv, px, py := GenerateInnerKey()
	sharedX, sharedY := curve.ScalarMult(publicX, publicY, priv.Bytes())

	buf := new(bytes.Buffer)
	buf.Write(sharedX.Bytes())
	buf.Write(sharedY.Bytes())
	key := sha3.Sum256(buf.Bytes())

	ciphertext := secretbox.Seal(nil, plaintext, nonce, &key)
	return px, py, ciphertext
}

// OnoinEncrypt returns a ciphertext that encrypts plaintext under
// all given keys.
func OnionEncrypt(publicXs, publicYs []*big.Int, nonce *[24]byte, plaintext []byte) (*big.Int, *big.Int, []byte) {
	x, y := big.NewInt(0), big.NewInt(0)
	for i := range publicXs {
		x, y = curve.Add(x, y, publicXs[i], publicYs[i])
	}
	return Encrypt(x, y, nonce, plaintext)
}

// Decrypt returns the plaintext message decrypted using private.
func Decrypt(private *big.Int, nonce *[24]byte, rx, ry *big.Int, ciphertext []byte) ([]byte, error) {
	sharedX, sharedY := curve.ScalarMult(rx, ry, private.Bytes())

	// derive a shared key
	buf := new(bytes.Buffer)
	buf.Write(sharedX.Bytes())
	buf.Write(sharedY.Bytes())
	key := sha3.Sum256(buf.Bytes())

	msg, auth := secretbox.Open(nil, ciphertext, nonce, &key)
	if !auth {
		return nil, errors.New("Misauthenticated msg")
	}
	return msg, nil
}

// OnoinDecrypt returns the plaintext message decyprted using all
// given keys.
func OnionDecrypt(privates []*big.Int, nonce *[24]byte, rx, ry *big.Int, ciphertext []byte) ([]byte, error) {
	private := big.NewInt(0)
	for _, p := range privates {
		private = private.Add(private, p)
	}
	return Decrypt(private, nonce, rx, ry, ciphertext)
}
