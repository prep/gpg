package agent

import (
	"crypto"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	internalrsa "github.com/prep/gpg/agent/internal/rsa"
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

// Decrypt decrypts ciphertext with this key. If opts is nil or of type
// *PKCS1v15DecryptOptions then PKCS#1 v1.5 decryption is performed. Otherwise
// opts must have type *OAEPOptions and OAEP decryption is done.
//
// This function is basically a copy of rsa.Decrypt().
func (key Key) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	switch pub := key.publicKey.(type) {
	case *rsa.PublicKey:
		priv := &internalrsa.PrivateKey{
			PrivateKey: rsa.PrivateKey{
				PublicKey: *pub,
			},
			DecryptFunc: key.decrypt,
		}

		if opts == nil {
			return internalrsa.DecryptPKCS1v15(rand, priv, ciphertext)
		}

		switch opts := opts.(type) {
		case *rsa.OAEPOptions:
			return internalrsa.DecryptOAEP(opts.Hash.New(), rand, priv, ciphertext, opts.Label)

		case *rsa.PKCS1v15DecryptOptions:
			if l := opts.SessionKeyLen; l > 0 {
				plaintext = make([]byte, l)
				if _, err := io.ReadFull(rand, plaintext); err != nil {
					return nil, err
				}
				if err := internalrsa.DecryptPKCS1v15SessionKey(rand, priv, ciphertext, plaintext); err != nil {
					return nil, err
				}

				return plaintext, nil
			}

			return internalrsa.DecryptPKCS1v15(rand, priv, ciphertext)

		default:
			return nil, errors.New("github.com/prep/gpg/agent: invalid options for Decrypt")
		}

	default:
		return nil, errors.New("github.com/prep/gpg/agent: unknown public key")
	}
}

// Sign signs msg with this key, possibly using entropy from rand. If opts is
// a *PSSOptions then the PSS algorithm will be used, otherwise PKCS#1 v1.5
// will be used.
//
// This function is basically a copy of rsa.Sign().
func (key Key) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	switch pub := key.publicKey.(type) {
	case *rsa.PublicKey:
		priv := &internalrsa.PrivateKey{
			PrivateKey: rsa.PrivateKey{
				PublicKey: *pub,
			},
			DecryptFunc: key.decrypt,
		}

		if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
			return internalrsa.SignPSS(rand, priv, pssOpts.Hash, msg, pssOpts)
		}

		return key.signPKCS1v15(msg, opts.HashFunc())

	default:
		return nil, errors.New("github.com/prep/gpg/agent: unknown public key")
	}
}

func (key Key) decrypt(c *big.Int) (*big.Int, error) {
	encCipherText, err := encodeRSACipherText(c.Bytes())
	if err != nil {
		return nil, err
	}

	key.conn.mu.Lock()
	defer key.conn.mu.Unlock()

	if err = key.conn.Raw(nil, "RESET"); err != nil {
		return nil, err
	}

	if err = key.conn.Raw(nil, "HAVEKEY %s", key.Keygrip); err != nil {
		return nil, err
	}

	if err = key.conn.Raw(nil, "SETKEY %s", key.Keygrip); err != nil {
		return nil, err
	}

	var response string
	respFunc := func(respType, data string) error {
		switch respType {
		case "INQUIRE":

			if err = key.conn.request("D %s\nEND\n", encode(string(encCipherText))); err != nil {
				return err
			}

		case "D":
			response = data
		}

		return nil
	}

	if err = key.conn.Raw(respFunc, "PKDECRYPT"); err != nil {
		return nil, err
	}

	plaintext, err := decodePlainText([]byte(response))
	if err != nil {
		return nil, err
	}

	return (&big.Int{}).SetBytes(plaintext), nil
}

func (key Key) signPKCS1v15(msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	var hashType string
	switch opts.HashFunc() {
	case crypto.MD5:
		hashType = "md5"
	case crypto.RIPEMD160:
		hashType = "rmd160"
	case crypto.SHA1:
		hashType = "sha1"
	case crypto.SHA224:
		hashType = "sha224"
	case crypto.SHA256:
		hashType = "sha256"
	case crypto.SHA384:
		hashType = "sha384"
	case crypto.SHA512:
		hashType = "sha512"
	case crypto.MD5SHA1:
		hashType = "tls-md5sha1"
	default:
		return nil, fmt.Errorf("%v: unknown hash type", opts.HashFunc())
	}

	if !opts.HashFunc().Available() {
		return nil, fmt.Errorf("%s: hash type is not available", hashType)
	}

	key.conn.mu.Lock()
	defer key.conn.mu.Unlock()

	if err := key.conn.Raw(nil, "RESET"); err != nil {
		return nil, err
	}

	if err := key.conn.Raw(nil, "SETKEY %s", key.Keygrip); err != nil {
		return nil, err
	}

	if err := key.conn.Raw(nil, "SETHASH --hash=%s %s", hashType, hex.EncodeToString(msg)); err != nil {
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
