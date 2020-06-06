// helper functinalities used to create mailbox messages
package mailbox

import (
	"golang.org/x/crypto/nacl/box"
)

func SealMail(theirKey *[32]byte, myKey *[32]byte, nonce *[24]byte, msg []byte) *Mail {
	ciphertext := box.Seal(nil, msg, nonce, theirKey, myKey)
	return &Mail{
		UserKey: (*theirKey)[:],
		Message: ciphertext,
	}
}

func OpenMail(theirKey *[32]byte, myKey *[32]byte, nonce *[24]byte, ciphertext []byte) []byte {
	msg, ok := box.Open(nil, ciphertext, nonce, theirKey, myKey)
	if !ok {
		return nil
	} else {
		return msg
	}
}

func MarshalMail(mail *Mail) []byte {
	b := make([]byte, 32+len(mail.Message))
	copy(b[:32], mail.UserKey)
	copy(b[32:], mail.Message)
	return b
}

func UnmarshalMail(b []byte) *Mail {
	return &Mail{
		UserKey: b[:32],
		Message: b[32:],
	}
}
