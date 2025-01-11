// Package api implements the MRAE API and common helpers.
package api

import (
	"crypto/cipher"
	"crypto/hmac"
	"hash"
	"testing"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"
	"github.com/stretchr/testify/require"
)

// Box is the interface for using MRAE AEAD primitives with asymmetric
// public key cryptography.
type Box interface {
	// DeriveSymmetricKey derives a MRAE AEAD symmetric key suitable for
	// use with the Box API from the provided X25519 public and private keys.
	DeriveSymmetricKey(key []byte, publicKey *x25519.PublicKey, privateKey *x25519.PrivateKey)

	// Seal seals ("boxes") the provided additional data and plaintext
	// via the MRAE AEAD primitive using a symmetric key derived from the
	// provided X25519 public and private keys, appending the result
	// to dst, returning the updated slice.  The nonce MUST be
	// aead.NonceSize() bytes long and SHOULD be unique for all time,
	// for a given public and private key tuple.
	//
	// The plaintext and dst must overlap exactly or not at all.  To reuse
	// plaintext's storage for encrypted output, use plaintext[:0] as dst.
	Seal(dst, nonce, plaintext, additionalData []byte, peersPublicKey *x25519.PublicKey, privateKey *x25519.PrivateKey) []byte

	// Open opens ("unboxes") the provided additional data and ciphertext
	// via the MRAE AEAD primitive using a symmetric key dervied from the
	// provided X25519 public and private keys and, if successful, appends
	// the resulting plaintext to dst, returning the updated slice. The
	// nonce MUST be aead.NonceSize() bytes long and SHOULD be unique for
	// all time, for a given public and private key tuple.
	//
	// The ciphertext and dst must overlap exactly or not at all.  To reuse
	// ciphertext's storage for the decrypted output, use ciphertext[:0] as dst.
	//
	// Even if the function fails, the contents of dst, up to it's capacity,
	// may be overwritten.
	Open(dst, nonce, plaintext, additionalData []byte, peersPublicKey *x25519.PublicKey, privateKey *x25519.PrivateKey) ([]byte, error)
}

// ECDHAndTweak applies the X25519 scalar multiply with the given public and
// private keys, and applies a HMAC based tweak to the resulting output.
func ECDHAndTweak(key []byte, publicKey *x25519.PublicKey, privateKey *x25519.PrivateKey, h func() hash.Hash, tweak []byte) {
	pmk := privateKey.DiffieHellman(publicKey)

	kdf := hmac.New(h, tweak)
	_, _ = kdf.Write(pmk[:])
	Bzero(pmk[:])
	tmp := kdf.Sum(nil)

	copy(key, tmp)
	Bzero(tmp)
}

// Bzero clears the slice.
func Bzero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// TestBoxIntegration tests a box implementation.
func TestBoxIntegration(t *testing.T, impl Box, ctor func([]byte) (cipher.AEAD, error), keySize int) {
	require := require.New(t)

	alicePub, alicePriv, err := x25519.GenerateKey(nil)
	require.NoError(err, "GenerateKey(Alice)")

	bobPub, bobPriv, err := x25519.GenerateKey(nil)
	require.NoError(err, "GenerateKey(Bob)")

	// Ensure that BoxSeal is equvialent to Derive + AEAD.Seal.
	k := make([]byte, keySize)
	impl.DeriveSymmetricKey(k, bobPub, alicePriv)
	aead, err := ctor(k)
	require.NoError(err, "aead.New(key)")

	nonceSize := aead.NonceSize()
	n := make([]byte, nonceSize)

	var aad [23]byte
	var msg [96]byte

	for i := range n {
		n[i] = byte(i)
	}
	for i := range aad {
		aad[i] = byte(i + nonceSize)
	}
	for i := range msg {
		msg[i] = byte(i + nonceSize + len(aad))
	}

	// Alice: Box
	ct := impl.Seal(nil, n, msg[:], aad[:], bobPub, alicePriv)

	// Compare sealed
	ctCmp := aead.Seal(nil, n, msg[:], aad[:])
	require.EqualValues(ctCmp, ct, "Box.Seal ?= Derive + AEAD.Seal")

	// Bob: Unbox
	pt, err := impl.Open(nil, n, ct, aad[:], alicePub, bobPriv)
	require.NoError(err, "BoxOpen")
	require.EqualValues(msg[:], pt, "Box.Open expected ?= plaintext")
}
