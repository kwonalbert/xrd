package mixnet

import (
	"bytes"
	"math/big"
	"testing"
)

func BenchmarkDecrypt(b *testing.B) {
	private, publicX, publicY := GenerateInnerKey()
	msg := []byte("hello world")

	var nonce [24]byte
	rx, ry, c := Encrypt(publicX, publicY, &nonce, msg)

	for i := 0; i < b.N; i++ {
		Decrypt(private, &nonce, rx, ry, c)
	}
}

func TestEncrypt(t *testing.T) {
	private, publicX, publicY := GenerateInnerKey()
	msg := []byte("hello world")

	var nonce [24]byte
	rx, ry, c := Encrypt(publicX, publicY, &nonce, msg)

	res, err := Decrypt(private, &nonce, rx, ry, c)
	if err != nil {
		t.Error(err)
	} else if !bytes.Equal(msg, res) {
		t.Error("Decryption failed")
	}
}

func TestOnionEncrypt(t *testing.T) {
	n := 10
	privates := make([]*big.Int, n)
	publicXs := make([]*big.Int, n)
	publicYs := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		private, publicX, publicY := GenerateInnerKey()
		privates[i] = private
		publicXs[i] = publicX
		publicYs[i] = publicY
	}
	msg := []byte("hello world")

	var nonce [24]byte
	rx, ry, c := OnionEncrypt(publicXs, publicYs, &nonce, msg)

	res, err := OnionDecrypt(privates, &nonce, rx, ry, c)
	if err != nil {
		t.Error(err)
	} else if !bytes.Equal(msg, res) {
		t.Error("Decryption failed")
	}
}
