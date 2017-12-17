package agent

import (
	"testing"

	"github.com/prep/gpg"
)

var conn *Conn

func init() {
	options := []string{
		"allow-pinentry-notify",
		"agent-awareness=2.1.0",
	}

	var err error
	if conn, err = Dial("../testdata/gnupg/S.gpg-agent", options); err != nil {
		panic(err.Error())
	}
}

func TestKey(t *testing.T) {
	keygrip := "C729393956A1361239C64EFB3DAC4D3735A003ED"

	key, err := conn.Key(keygrip)
	if err != nil {
		t.Fatalf("Key(%s): %s", keygrip, err)
	}

	if key.Keygrip != keygrip {
		t.Errorf("expected keygrip %q, but got %q", keygrip, key.Keygrip)
	}
}

func TestKeyWithUnknownKeygrip(t *testing.T) {
	_, err := conn.Key("0000000000000000000000000000000000000000")
	switch v := err.(type) {
	case nil:
		t.Fatal("expected error on Key() call with invalid keygrip, but got none")
	case Error:
		if v.Code != 67108891 {
			t.Fatalf("expected error code 67108891, but got %d instead", v.Code)
		}
	default:
		t.Fatalf("expected a gpg-agent error, but got this error instead: %s", err)
	}
}

func TestKeys(t *testing.T) {
	keys, err := conn.Keys()
	if err != nil {
		t.Fatalf("Keylist(): %s", err)
	}

	if numKeys := len(keys); numKeys != 4 {
		t.Fatalf("expected 4 keys, but got %d", numKeys)
	}

	for _, key := range keys {
		switch key.Keygrip {
		case "FF47135C1C28599504C27AC6AE1117B6E02079BD": // Primary key
		case "C729393956A1361239C64EFB3DAC4D3735A003ED": // Signing key
		case "3F0803C0B90C2F86A1153F7CC9ACC11AF1CCDA70": // Encryption key
		case "805E7F4F2E2990424218F11EBCEB53B6C6FAF2F4": // Authentication key
		default:
			t.Fatalf("%s: unknown keygrip returned by Keylist()", key.Keygrip)
		}
	}
}

func TestReadKey(t *testing.T) {
	keygrip := "FF47135C1C28599504C27AC6AE1117B6E02079BD"

	publicKey, err := conn.ReadKey(keygrip)
	if err != nil {
		t.Fatalf("ReadKey(%s): %s", keygrip, err)
	}

	if kg := gpg.Keygrip(publicKey); kg != keygrip {
		t.Fatalf("expected keygrip %q, but got %q", keygrip, kg)
	}
}

func TestReadKeyWithUnknownKeygrip(t *testing.T) {
	_, err := conn.ReadKey("0000000000000000000000000000000000000000")
	switch v := err.(type) {
	case nil:
		t.Fatal("expected error on Key() call with invalid keygrip, but got none")
	case Error:
		if v.Code != 67141713 {
			t.Fatalf("expected error code 67141713, but got %d instead", v.Code)
		}
	default:
		t.Fatalf("expected a gpg-agent error, but got this error instead: %s", err)
	}
}

func TestVersion(t *testing.T) {
	version, err := conn.Version()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if len(version) == 0 {
		t.Errorf("expected a version string to return, but got nothing")
	}
}
