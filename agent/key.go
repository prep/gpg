package agent

import (
	"crypto"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// KeyType describes the type of the key.
type KeyType int

// These constants define the possible KeyType values.
const (
	StoredOnDisk KeyType = iota
	StoredOnCard
	StoredUnknown
	StoredMissing
)

// KeyProtection describes the key project type.
type KeyProtection int

// These constants define the possible KeyProtection values.
const (
	ProtByPassphrase KeyProtection = iota
	ProtByNothing
	ProtUnknown
)

// Key describes the information gpg-agent exposes about a key.
type Key struct {
	Keygrip     string
	Type        KeyType
	SerialNo    string
	CardID      string
	Cached      bool
	Protection  KeyProtection
	Fingerprint string
	TimeToLive  string

	conn      *Conn
	publicKey crypto.PublicKey
}

// Public returns this key's public key.
func (key Key) Public() crypto.PublicKey {
	return key.publicKey
}

// Decrypt decrypts ciphertext with priv. If opts is nil or of type
// *PKCS1v15DecryptOptions then PKCS#1 v1.5 decryption is performed. Otherwise
// opts must have type *OAEPOptions and OAEP decryption is done.
//
// This function is basically a copy of rsa.Decrypt().
func (key Key) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	if opts == nil {
		return decryptPKCS1v15(rand, key, ciphertext)
	}

	switch opts := opts.(type) {
	case *rsa.OAEPOptions:
		return decryptOAEP(opts.Hash.New(), rand, key, ciphertext, opts.Label)

	case *rsa.PKCS1v15DecryptOptions:
		if l := opts.SessionKeyLen; l > 0 {
			plaintext = make([]byte, l)
			if _, err := io.ReadFull(rand, plaintext); err != nil {
				return nil, err
			}
			if err := decryptPKCS1v15SessionKey(rand, key, ciphertext, plaintext); err != nil {
				return nil, err
			}

			return plaintext, nil
		}

		return decryptPKCS1v15(rand, key, ciphertext)

	default:
		return nil, errors.New("github.com/prep/gpg/agent: invalid options for Decrypt")
	}
}

func (key Key) decrypt(ciphertext []byte) ([]byte, error) {
	encCipherText, err := encodeRSACipherText(ciphertext)
	if err != nil {
		return nil, err
	}

	key.conn.Lock()
	defer key.conn.Unlock()

	if err := key.conn.Raw(nil, "RESET"); err != nil {
		return nil, err
	}

	if err := key.conn.Raw(nil, "HAVEKEY %s", key.Keygrip); err != nil {
		return nil, err
	}

	if err := key.conn.Raw(nil, "SETKEY %s", key.Keygrip); err != nil {
		return nil, err
	}

	var response string
	respFunc := func(respType, data string) error {
		switch respType {
		case "INQUIRE":
			if err := key.conn.request("D %s\nEND\n", encode(string(encCipherText))); err != nil {
				return err
			}

		case "D":
			response = data
		}

		return nil
	}

	if err := key.conn.Raw(respFunc, "PKDECRYPT"); err != nil {
		return nil, err
	}

	return decodePlainText([]byte(response))
}

func (key Key) sign(msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	var hashType string

	switch opts.HashFunc() {
	case crypto.MD5:
		hashType = "md5"
	case crypto.RIPEMD160:
		hashType = "rmd160"
	case crypto.SHA1:
		hashType = "sha1"
	case crypto.SHA256:
		hashType = "sha256"
	case crypto.MD5SHA1:
		hashType = "tls-md5sha1"
	default:
		return nil, fmt.Errorf("%v: unknown hash type", opts.HashFunc())
	}

	if !opts.HashFunc().Available() {
		return nil, fmt.Errorf("%s: hash type is not available", hashType)
	}

	hash := opts.HashFunc().New()
	hash.Write(msg)
	sum := hex.EncodeToString(hash.Sum(nil))

	key.conn.Lock()
	defer key.conn.Unlock()

	if err := key.conn.Raw(nil, "RESET"); err != nil {
		return nil, err
	}

	if err := key.conn.Raw(nil, "SETKEY %s", key.Keygrip); err != nil {
		return nil, err
	}

	if err := key.conn.Raw(nil, "SETHASH --hash=%s %s", hashType, sum); err != nil {
		return nil, err
	}

	var response string
	respFunc := func(respType, data string) error {
		switch respType {
		case "INQUIRE":
			if err := key.conn.request("END"); err != nil {
				return err
			}

		case "D":
			response = data
		}

		return nil
	}

	if err := key.conn.Raw(respFunc, "PKSIGN"); err != nil {
		return nil, err
	}

	return decodeRSASignature([]byte(response))
}
