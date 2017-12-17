package agent

import (
	"bufio"
	"crypto"
	"fmt"
	"io/ioutil"
	"net"
	// "os"
	"strings"
	"sync"
)

var (
	// debug = os.Stdout
	debug = ioutil.Discard
)

// ResponseFunc defines the function handler for the Raw function.
type ResponseFunc func(respType, data string) error

// Conn represents a single connection to a GPG agent.
type Conn struct {
	c net.Conn
	r *bufio.Reader
	sync.Mutex
}

// Dial connects to the specified unix domain socket and checks if there is a
// live GPG agent on the other end.
func Dial(filename string, options []string) (*Conn, error) {
	c, err := net.Dial("unix", filename)
	if err != nil {
		return nil, err
	}

	conn := &Conn{c: c, r: bufio.NewReader(c)}
	if err = conn.response(func(string, string) error { return nil }); err != nil {
		return nil, err
	}

	for _, option := range options {
		if err := conn.Raw(nil, "OPTION %s", option); err != nil {
			return nil, err
		}
	}

	return conn, nil
}

// request sends a request to the pgp-agent and then returns its response.
func (conn *Conn) request(format string, a ...interface{}) error {
	req := fmt.Sprintf(format+"\n", a...)
	fmt.Fprintf(debug, "> %s", req)

	_, err := conn.c.Write([]byte(req))
	return err
}

// response reads the gpg-agent's response after a request has been issued.
func (conn *Conn) response(f ResponseFunc) error {
	var funcErr error
	if f == nil {
		f = func(respType, data string) error { return nil }
	}

	for {
		line, err := conn.r.ReadString('\n')
		if err != nil {
			return err
		}

		fmt.Fprintf(debug, "< %s", line)

		line = strings.TrimSpace(line)
		switch {
		case line == "OK" || strings.HasPrefix(line, "OK "):
			return funcErr

		case strings.HasPrefix(line, "ERR "):
			if funcErr != nil {
				return funcErr
			}

			return NewError(line)
		}

		if funcErr != nil {
			continue
		}

		switch {
		case strings.HasPrefix(line, "S "):
			funcErr = f("S", line[2:])

		case strings.HasPrefix(line, "D "):
			funcErr = f("D", decode(line[2:]))

		case strings.HasPrefix(line, "INQUIRE "):
			funcErr = f("INQUIRE", line[8:])

		case strings.HasPrefix(line, "# "):
			funcErr = f("#", line[2:])
		}
	}
}

// Close this connection.
func (conn *Conn) Close() error {
	conn.Lock()
	defer conn.Unlock()

	conn.r = nil
	return conn.c.Close()
}

func keyScan(key *Key, line string) error {
	parts := strings.Split(line, " ")
	if len(parts) != 10 {
		return fmt.Errorf("illegal format for KEYINFO line")
	}

	for i, part := range parts[1:] {
		switch i {
		case 0:
			key.Keygrip = part
		case 1:
			switch part {
			case "D":
				key.Type = StoredOnDisk
			case "T":
				key.Type = StoredOnCard
			case "-":
				key.Type = StoredMissing
			default:
				key.Type = StoredUnknown
			}
		case 2:
			key.SerialNo = part
		case 3:
			key.CardID = part
		case 4:
			key.Cached = (part == "1")
		case 5:
			switch part {
			case "P":
				key.Protection = ProtByPassphrase
			case "C":
				key.Protection = ProtByNothing
			default:
				key.Protection = ProtUnknown
			}
		case 6:
			if part != "-" {
				key.Fingerprint = part
			}
		case 7:
			if part != "-" {
				key.TimeToLive = part
			}
		}
	}

	return nil
}

// Key returns the key information for the key with the specified keygrip.
func (conn *Conn) Key(keygrip string) (Key, error) {
	var key Key
	respFunc := func(respType, data string) (err error) {
		if respType != "S" || !strings.HasPrefix(data, "KEYINFO ") {
			return nil
		}

		return keyScan(&key, data)
	}

	conn.Lock()
	defer conn.Unlock()

	err := conn.Raw(respFunc, "KEYINFO --ssh-fpr %s", keygrip)
	if err != nil {
		return Key{}, err
	}

	key.conn = conn
	if key.publicKey, err = conn.readKey(key.Keygrip); err != nil {
		return Key{}, err
	}

	return key, nil
}

// Keys returns a list of available keys.
func (conn *Conn) Keys() ([]Key, error) {
	var keyList []Key
	respFunc := func(respType, data string) error {
		if respType != "S" || !strings.HasPrefix(data, "KEYINFO ") {
			return nil
		}

		var key Key
		if err := keyScan(&key, data); err != nil {
			return err
		}

		keyList = append(keyList, key)
		return nil
	}

	conn.Lock()
	defer conn.Unlock()

	err := conn.Raw(respFunc, "KEYINFO --list --ssh-fpr")
	if err != nil {
		return nil, err
	}

	for i, key := range keyList {
		key.conn = conn
		if keyList[i].publicKey, err = conn.readKey(key.Keygrip); err != nil {
			return nil, err
		}
	}

	return keyList, nil
}

// Raw executes a command and pipes its results to the specified ResponseFunc
// parameter.
func (conn *Conn) Raw(f ResponseFunc, format string, a ...interface{}) error {
	if err := conn.request(format, a...); err != nil {
		return err
	}

	return conn.response(f)
}

// ReadKey returns the public key for the key with the specified keygrip.
func (conn *Conn) ReadKey(keygrip string) (crypto.PublicKey, error) {
	conn.Lock()
	defer conn.Unlock()

	return conn.readKey(keygrip)
}

func (conn *Conn) readKey(keygrip string) (crypto.PublicKey, error) {
	var key string
	respFunc := func(respType, data string) error {
		if respType == "D" {
			key = data
		}

		return nil
	}

	if err := conn.Raw(respFunc, "READKEY %s", keygrip); err != nil {
		return nil, err
	}

	publicKey, err := decodeRSAPublicKey(key)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

// Version returns the version number of gpg-agent.
func (conn *Conn) Version() (string, error) {
	var version string
	respFunc := func(respType, data string) error {
		if respType == "D" {
			version = data
		}

		return nil
	}

	conn.Lock()
	defer conn.Unlock()

	if err := conn.Raw(respFunc, "GETINFO version"); err != nil {
		return "", err
	}

	return version, nil
}
