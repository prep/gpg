package agent

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/abesto/sexp"
)

// These errors may be returned from the functions related to s-expression
// encoding and decoding.
var (
	ErrUnknownFormat = errors.New("s-expression is in unknown format")
	ErrNotPublicKey  = errors.New("s-expression is not a public key")
	ErrNotSignature  = errors.New("s-expression is not a signature")
)

// (value%u)
func decodePlainText(data []byte) ([]byte, error) {
	exp, err := sexp.Unmarshal(data)
	if err != nil {
		return nil, err
	}
	if len(exp) != 2 {
		return nil, ErrUnknownFormat
	}

	name, ok := exp[0].([]byte)
	if !ok || string(name) != "value" {
		return nil, ErrUnknownFormat
	}

	value, ok := exp[1].([]byte)
	if !ok {
		return nil, ErrUnknownFormat
	}

	return value, nil
}

// (10:public-key(3:rsa(1:n)(1:e)))
func decodeRSAPublicKey(data string) (crypto.PublicKey, error) {
	exp, err := sexp.Unmarshal([]byte(data))
	if err != nil {
		return nil, err
	}
	if len(exp) != 2 {
		return nil, ErrUnknownFormat
	}

	name, ok := exp[0].([]byte)
	if !ok || string(name) != "public-key" {
		return nil, ErrNotPublicKey
	}

	algol, ok := exp[1].([]interface{})
	if !ok {
		return nil, ErrUnknownFormat
	}
	if len(algol) != 3 {
		return nil, ErrUnknownFormat
	}

	algo, ok := algol[0].([]byte)
	if !ok {
		return nil, ErrUnknownFormat
	}

	switch string(algo) {
	case "rsa":
		nl, ok := algol[1].([]interface{})
		if !ok {
			return nil, ErrUnknownFormat
		}

		el, ok := algol[2].([]interface{})
		if !ok {
			return nil, ErrUnknownFormat
		}

		if len(nl) != 2 || len(el) != 2 {
			return nil, ErrUnknownFormat
		}

		if name, ok := nl[0].([]byte); !ok || string(name) != "n" {
			return nil, ErrUnknownFormat
		}

		n, ok := nl[1].([]byte)
		if !ok {
			return nil, ErrUnknownFormat
		}

		if name, ok := el[0].([]byte); !ok || string(name) != "e" {
			return nil, ErrUnknownFormat
		}

		e, ok := el[1].([]byte)
		if !ok {
			return nil, ErrUnknownFormat
		}

		return rsa.PublicKey{
			N: (&big.Int{}).SetBytes(n),
			E: int((&big.Int{}).SetBytes(e).Int64()),
		}, nil

	default:
		return nil, fmt.Errorf("%s: unknown algorithm", string(algo))
	}
}

// (7:sig-val(3:rsa(1:s)))
func decodeRSASignature(data []byte) ([]byte, error) {
	exp, err := sexp.Unmarshal(data)
	if err != nil {
		return nil, err
	}
	if len(exp) != 2 {
		return nil, ErrUnknownFormat
	}

	name, ok := exp[0].([]byte)
	if !ok || string(name) != "sig-val" {
		return nil, ErrNotSignature
	}

	algol, ok := exp[1].([]interface{})
	if !ok {
		return nil, ErrUnknownFormat
	}
	if len(algol) != 2 {
		return nil, ErrUnknownFormat
	}

	algo, ok := algol[0].([]byte)
	if !ok {
		return nil, ErrUnknownFormat
	}

	switch string(algo) {
	case "rsa":
		l, ok := algol[1].([]interface{})
		if !ok || len(l) != 2 {
			return nil, ErrUnknownFormat
		}

		if name, ok := l[0].([]byte); !ok || string(name) != "s" {
			return nil, ErrUnknownFormat
		}

		signature, ok := l[1].([]byte)
		if !ok {
			return nil, ErrUnknownFormat
		}

		return signature, nil

	default:
		return nil, fmt.Errorf("%s: unknown algorithm", string(algo))
	}
}

// (enc-val(rsa(a%m)))
func encodeRSACipherText(cyphertext []byte) ([]byte, error) {
	sexpText := []interface{}{
		[]byte("enc-val"),
		[]interface{}{
			[]byte("rsa"),
			[]interface{}{
				[]byte("a"),
				cyphertext,
			},
		},
	}

	return sexp.Marshal(sexpText, true)
}
