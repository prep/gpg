package rsa

import (
	"crypto/rsa"
	"crypto/subtle"
	"hash"
	"io"
	"math/big"
)

// DecryptOAEP decrypts ciphertext using RSA-OAEP.
//
// OAEP is parameterised by a hash function that is used as a random oracle.
// Encryption and decryption of a given message must use the same hash function
// and sha256.New() is a reasonable choice.
//
// The random parameter, if not nil, is used to blind the private-key operation
// and avoid timing side-channel attacks. Blinding is purely internal to this
// function – the random data need not match that used when encrypting.
//
// The label parameter must match the value given when encrypting. See
// EncryptOAEP for details.
func DecryptOAEP(hash hash.Hash, random io.Reader, priv *PrivateKey, ciphertext []byte, label []byte) ([]byte, error) {
	if err := checkPub(&priv.PublicKey); err != nil {
		return nil, err
	}
	k := (priv.N.BitLen() + 7) / 8
	if len(ciphertext) > k ||
		k < hash.Size()*2+2 {
		return nil, rsa.ErrDecryption
	}

	c := new(big.Int).SetBytes(ciphertext)

	m, err := decrypt(random, priv, c)
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
	em := leftPad(m.Bytes(), k)

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

// DecryptPKCS1v15 decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5.
// If rand != nil, it uses RSA blinding to avoid timing side-channel attacks.
//
// Note that whether this function returns an error or not discloses secret
// information. If an attacker can cause this function to run repeatedly and
// learn whether each instance returned an error then they can decrypt and
// forge signatures as if they had the private key. See
// DecryptPKCS1v15SessionKey for a way of solving this problem.
func DecryptPKCS1v15(rand io.Reader, priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	if err := checkPub(&priv.PublicKey); err != nil {
		return nil, err
	}
	valid, out, index, err := decryptPKCS1v15(rand, priv, ciphertext)
	if err != nil {
		return nil, err
	}
	if valid == 0 {
		return nil, rsa.ErrDecryption
	}
	return out[index:], nil
}

// DecryptPKCS1v15SessionKey decrypts a session key using RSA and the padding scheme from PKCS#1 v1.5.
// If rand != nil, it uses RSA blinding to avoid timing side-channel attacks.
// It returns an error if the ciphertext is the wrong length or if the
// ciphertext is greater than the public modulus. Otherwise, no error is
// returned. If the padding is valid, the resulting plaintext message is copied
// into key. Otherwise, key is unchanged. These alternatives occur in constant
// time. It is intended that the user of this function generate a random
// session key beforehand and continue the protocol with the resulting value.
// This will remove any possibility that an attacker can learn any information
// about the plaintext.
// See ``Chosen Ciphertext Attacks Against Protocols Based on the RSA
// Encryption Standard PKCS #1'', Daniel Bleichenbacher, Advances in Cryptology
// (Crypto '98).
//
// Note that if the session key is too small then it may be possible for an
// attacker to brute-force it. If they can do that then they can learn whether
// a random value was used (because it'll be different for the same ciphertext)
// and thus whether the padding was correct. This defeats the point of this
// function. Using at least a 16-byte key will protect against this attack.
func DecryptPKCS1v15SessionKey(rand io.Reader, priv *PrivateKey, ciphertext []byte, key []byte) error {
	if err := checkPub(&priv.PublicKey); err != nil {
		return err
	}
	k := (priv.N.BitLen() + 7) / 8
	if k-(len(key)+3+8) < 0 {
		return rsa.ErrDecryption
	}

	valid, em, index, err := decryptPKCS1v15(rand, priv, ciphertext)
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

// decryptPKCS1v15 decrypts ciphertext using priv and blinds the operation if
// rand is not nil. It returns one or zero in valid that indicates whether the
// plaintext was correctly structured. In either case, the plaintext is
// returned in em so that it may be read independently of whether it was valid
// in order to maintain constant memory access patterns. If the plaintext was
// valid then index contains the index of the original message in em.
func decryptPKCS1v15(rand io.Reader, priv *PrivateKey, ciphertext []byte) (valid int, em []byte, index int, err error) {
	k := (priv.N.BitLen() + 7) / 8
	if k < 11 {
		err = rsa.ErrDecryption
		return
	}

	c := new(big.Int).SetBytes(ciphertext)
	m, err := decrypt(rand, priv, c)
	if err != nil {
		return
	}

	em = leftPad(m.Bytes(), k)
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
