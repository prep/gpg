// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agent

import (
	"crypto"
	"crypto/rsa"
	"crypto/subtle"
	"hash"
	"io"
)

// decrypter desribes an unfortunately needed interface, because the
// rsa.Decrypt* functions require a private key that the user might not have
// when it is stored in a card.
type decrypter interface {
	Public() crypto.PublicKey
	decrypt(ciphertext []byte) ([]byte, error)
}

type signer interface {
	Public() crypto.PublicKey
	decrypt(ciphertext []byte) ([]byte, error)
	sign(msg []byte, opts crypto.SignerOpts) ([]byte, error)
}

// decryptPKCS1v15 is a modified version of rsa.DecryptPKCS1v15().
func decryptPKCS1v15(rand io.Reader, dec decrypter, ciphertext []byte) ([]byte, error) {
	valid, out, index, err := decryptPKCS1v15Common(rand, dec, ciphertext)
	if err != nil {
		return nil, err
	}
	if valid == 0 {
		return nil, rsa.ErrDecryption
	}
	return out[index:], nil
}

// decryptPKCS1v15SessionKey is a modified version of rsa.DecryptPKCS1v15SessionKey().
func decryptPKCS1v15SessionKey(rand io.Reader, dec decrypter, ciphertext []byte, key []byte) error {
	pub, ok := dec.Public().(rsa.PublicKey)
	if !ok {
		return rsa.ErrDecryption
	}

	k := (pub.N.BitLen() + 7) / 8
	if k-(len(key)+3+8) < 0 {
		return rsa.ErrDecryption
	}

	valid, em, index, err := decryptPKCS1v15Common(rand, dec, ciphertext)
	if err != nil {
		return err
	}

	if len(em) != k {
		// This should be impossible because decryptPKCS1v15 always
		// returns the full slice.
		return rsa.ErrDecryption
	}

	valid &= subtle.ConstantTimeEq(int32(len(em)-index), int32(len(key)))
	subtle.ConstantTimeCopy(valid, key, em[len(em)-len(key):])
	return nil
}

// decryptPKCS1v15Common is a modified version of rsa.decryptPKCS1v15().
func decryptPKCS1v15Common(rand io.Reader, dec decrypter, ciphertext []byte) (valid int, em []byte, index int, err error) {
	pub, ok := dec.Public().(rsa.PublicKey)
	if !ok {
		err = rsa.ErrDecryption
		return
	}

	k := (pub.N.BitLen() + 7) / 8
	if k < 11 {
		err = rsa.ErrDecryption
		return
	}

	m, err := dec.decrypt(ciphertext)
	if err != nil {
		return
	}

	em = leftPad(m, k)
	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)
	secondByteIsTwo := subtle.ConstantTimeByteEq(em[1], 2)

	// The remainder of the plaintext must be a string of non-zero random
	// octets, followed by a 0, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the zero.
	//   index: the offset of the first zero byte.
	lookingForIndex := 1

	for i := 2; i < len(em); i++ {
		equals0 := subtle.ConstantTimeByteEq(em[i], 0)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals0, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals0, 0, lookingForIndex)
	}

	// The PS padding must be at least 8 bytes long, and it starts two
	// bytes into em.
	validPS := subtle.ConstantTimeLessOrEq(2+8, index)

	valid = firstByteIsZero & secondByteIsTwo & (^lookingForIndex & 1) & validPS
	index = subtle.ConstantTimeSelect(valid, index+1, 0)
	return valid, em, index, nil
}

// decryptOAEP is a modified version of rsa.DecryptOAEP().
func decryptOAEP(hash hash.Hash, random io.Reader, dec decrypter, ciphertext []byte, label []byte) ([]byte, error) {
	pub, ok := dec.Public().(rsa.PublicKey)
	if !ok {
		return nil, rsa.ErrDecryption
	}

	k := (pub.N.BitLen() + 7) / 8
	if len(ciphertext) > k ||
		k < hash.Size()*2+2 {
		return nil, rsa.ErrDecryption
	}

	m, err := dec.decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	// Converting the plaintext number to bytes will strip any
	// leading zeros so we may have to left pad. We do this unconditionally
	// to avoid leaking timing information. (Although we still probably
	// leak the number of leading zeros. It's not clear that we can do
	// anything about this.)
	em := leftPad(m, k)

	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)

	seed := em[1 : hash.Size()+1]
	db := em[hash.Size()+1:]

	mgf1XOR(seed, hash, db)
	mgf1XOR(db, hash, seed)

	lHash2 := db[0:hash.Size()]

	// We have to validate the plaintext in constant time in order to avoid
	// attacks like: J. Manger. A Chosen Ciphertext Attack on RSA Optimal
	// Asymmetric Encryption Padding (OAEP) as Standardized in PKCS #1
	// v2.0. In J. Kilian, editor, Advances in Cryptology.
	lHash2Good := subtle.ConstantTimeCompare(lHash, lHash2)

	// The remainder of the plaintext must be zero or more 0x00, followed
	// by 0x01, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the 0x01
	//   index: the offset of the first 0x01 byte
	//   invalid: 1 iff we saw a non-zero byte before the 0x01.
	var lookingForIndex, index, invalid int
	lookingForIndex = 1
	rest := db[hash.Size():]

	for i := 0; i < len(rest); i++ {
		equals0 := subtle.ConstantTimeByteEq(rest[i], 0)
		equals1 := subtle.ConstantTimeByteEq(rest[i], 1)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals1, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals1, 0, lookingForIndex)
		invalid = subtle.ConstantTimeSelect(lookingForIndex&^equals0, 1, invalid)
	}

	if firstByteIsZero&lHash2Good&^invalid&^lookingForIndex != 1 {
		return nil, rsa.ErrDecryption
	}

	return rest[index+1:], nil
}

// incCounter increments a four byte, big-endian counter.
func incCounter(c *[4]byte) {
	if c[3]++; c[3] != 0 {
		return
	}
	if c[2]++; c[2] != 0 {
		return
	}
	if c[1]++; c[1] != 0 {
		return
	}
	c[0]++
}

// mgf1XOR XORs the bytes in out with a mask generated using the MGF1 function
// specified in PKCS#1 v2.1.
func mgf1XOR(out []byte, hash hash.Hash, seed []byte) {
	var counter [4]byte
	var digest []byte

	done := 0
	for done < len(out) {
		hash.Write(seed)
		hash.Write(counter[0:4])
		digest = hash.Sum(digest[:0])
		hash.Reset()

		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] ^= digest[i]
			done++
		}
		incCounter(&counter)
	}
}

// leftPad returns a new slice of length size. The contents of input are right
// aligned in the new slice.
func leftPad(input []byte, size int) (out []byte) {
	n := len(input)
	if n > size {
		n = size
	}
	out = make([]byte, size)
	copy(out[len(out)-n:], input)
	return
}
