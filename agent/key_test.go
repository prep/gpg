package agent

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	// Silent imports to make the hash type in crypto.SignerOpts work.
	_ "crypto/md5"
	_ "crypto/sha1"
	"crypto/sha256"

	"github.com/prep/gpg"
)

func TestPublic(t *testing.T) {
	keygrip := "FF47135C1C28599504C27AC6AE1117B6E02079BD"

	key, err := conn.Key(keygrip)
	if err != nil {
		t.Fatalf("Key(%s): %s", keygrip, err)
	}

	if kg := gpg.Keygrip(key.Public()); kg != keygrip {
		t.Fatalf("expected keygrip %q, but got %q", keygrip, kg)
	}
}

func TestDecryptWithPKCS1v15(t *testing.T) {
	keygrip := "3F0803C0B90C2F86A1153F7CC9ACC11AF1CCDA70"
	key, err := conn.Key(keygrip)
	if err != nil {
		t.Fatalf("Key(%s): %s", keygrip, err)
	}

	pub := key.Public().(*rsa.PublicKey)
	message := []byte("Hello World PKCS1v15")

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, message)
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

	pub := key.Public().(*rsa.PublicKey)
	message := []byte("Hello World OAEP")
	label := []byte("label")

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, message, label)
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

func TestSignWithPKCS1v15(t *testing.T) {
	keygrip := "C729393956A1361239C64EFB3DAC4D3735A003ED"

	key, err := conn.Key(keygrip)
	if err != nil {
		t.Fatalf("Key(%s): %s", keygrip, err)
	}

	msg := []byte("Hello World")
	hashed := sha256.Sum256(msg)

	sig, err := key.Sign(nil, hashed[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign(%s): %s", keygrip, err)
	}

	rsaPub := key.publicKey.(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hashed[:], sig); err != nil {
		t.Fatalf("VerifyPKCS1v15(): %s", err)
	}
}

func TestSignWithPSS(t *testing.T) {
	keygrip := "C729393956A1361239C64EFB3DAC4D3735A003ED"

	key, err := conn.Key(keygrip)
	if err != nil {
		t.Fatalf("Key(%s): %s", keygrip, err)
	}

	msg := []byte("Hello World")
	hashed := sha256.Sum256(msg)

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	}

	sig, err := key.Sign(rand.Reader, hashed[:], opts)
	if err != nil {
		t.Fatalf("Sign(%s): %s", keygrip, err)
	}

	rsaPub := key.publicKey.(*rsa.PublicKey)
	if err := rsa.VerifyPSS(rsaPub, crypto.SHA256, hashed[:], sig, opts); err != nil {
		t.Fatalf("VerifyPSS(): %s", err)
	}
}
