package gpg

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/hex"
	"strings"
)

// Keygrip returns the keygrip of an RSA public key, or an empty string when
// the public key is of a different type.
func Keygrip(publicKey crypto.PublicKey) string {
	sum := sha1.New()

	switch key := publicKey.(type) {
	case rsa.PublicKey:
		sum.Write([]byte{0})
		sum.Write(key.N.Bytes())
		return strings.ToUpper(hex.EncodeToString(sum.Sum(nil)))

	case *rsa.PublicKey:
		sum.Write([]byte{0})
		sum.Write(key.N.Bytes())
		return strings.ToUpper(hex.EncodeToString(sum.Sum(nil)))
	}

	return ""
}
