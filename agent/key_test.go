package agent

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"testing"

	// Silent imports to make the hash type in crypto.SignerOpts work.
	_ "crypto/md5"
	_ "crypto/sha1"
	"crypto/sha256"

	"github.com/prep/gpg"
)

func TestPublic(t *testing.T) {
	keygrip := "FF47135C1C28599504C27AC6AE1117B6E02079BD"

	keyInfo, err := conn.Key(keygrip)
	if err != nil {
		t.Fatalf("Key(%s): %s", keygrip, err)
	}

	if kg := gpg.Keygrip(keyInfo.Public()); kg != keygrip {
		t.Fatalf("expected keygrip %q, but got %q", keygrip, kg)
	}
}

func TestDecryptWithPKCS1v15(t *testing.T) {
	keygrip := "3F0803C0B90C2F86A1153F7CC9ACC11AF1CCDA70"
	key, err := conn.Key(keygrip)
	if err != nil {
		t.Fatalf("Key(%s): %s", keygrip, err)
	}

	pub := key.Public().(rsa.PublicKey)
	message := []byte("Hello World PKCS1v15")

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &pub, message)
	if err != nil {
		t.Fatalf("EncryptPKCS1v15(): %s", err)
	}

	plaintext, err := key.Decrypt(nil, ciphertext, nil)
	if err != nil {
		t.Fatalf("key.Decrypt(): %s", err)
	}

	if !bytes.Equal(plaintext, message) {
		t.Fatalf("plaintext message is %q, but expected %q", string(plaintext), string(message))
	}
}

func TestDecryptWithOAEP(t *testing.T) {
	keygrip := "3F0803C0B90C2F86A1153F7CC9ACC11AF1CCDA70"
	key, err := conn.Key(keygrip)
	if err != nil {
		t.Fatalf("Key(%s): %s", keygrip, err)
	}

	pub := key.Public().(rsa.PublicKey)
	message := []byte("Hello World OAEP")
	label := []byte("label")

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &pub, message, label)
	if err != nil {
		t.Fatalf("EncryptOAEP(): %s", err)
	}

	opts := &rsa.OAEPOptions{
		Hash:  crypto.SHA256,
		Label: label,
	}

	plaintext, err := key.Decrypt(nil, ciphertext, opts)
	if err != nil {
		t.Fatalf("key.Decrypt(): %s", err)
	}

	if !bytes.Equal(plaintext, message) {
		t.Fatalf("plaintext message is %q, but expected %q", string(plaintext), string(message))
	}
}

var signatures = []struct {
	Hash      crypto.Hash
	Signature string // The first 32 bytes of the signature
}{
	{crypto.MD5, "8ba8662fe385d1c6435a3842f659af9c"},
	{crypto.SHA1, "b95f76bf0a693e2e1be58d02a618be1c"},
	{crypto.SHA256, "3cd52395afb3d63dc8b9b1669230bdab"},
}

func TestSign(t *testing.T) {
	msg := []byte("Hello World")
	keygrip := "C729393956A1361239C64EFB3DAC4D3735A003ED"

	key, err := conn.Key(keygrip)
	if err != nil {
		t.Fatalf("Key(%s): %s", keygrip, err)
	}

	for _, signature := range signatures {
		sig, err := key.sign(msg, crypto.Hash(signature.Hash))
		if err != nil {
			t.Errorf("Sign(): %s", err)
			continue
		}

		if v := len(sig); v != 256 {
			t.Errorf("signature has a length of %d, but expected 256 bytes", v)
			continue
		}

		if v := hex.EncodeToString(sig)[:32]; v != signature.Signature {
			t.Errorf("expected signature didn't match: %s", v)
			continue
		}
	}
}
