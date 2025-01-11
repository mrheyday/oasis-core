// Package deoxysii implements the Deoxys-II-256-128 based MRAE boxes.
package deoxysii

import (
	"crypto/sha512"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"
	"github.com/oasisprotocol/deoxysii"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/mrae/api"
)

var (
	// Box is the asymmetric "Box" interface implementation.
	Box = &boxImpl{}

	boxKDFTweak = []byte("MRAE_Box_Deoxys-II-256-128")
)

type boxImpl struct{}

func (impl *boxImpl) DeriveSymmetricKey(key []byte, publicKey *x25519.PublicKey, privateKey *x25519.PrivateKey) {
	api.ECDHAndTweak(key, publicKey, privateKey, sha512.New512_256, boxKDFTweak)
}

func (impl *boxImpl) Seal(dst, nonce, plaintext, additionalData []byte, peersPublicKey *x25519.PublicKey, privateKey *x25519.PrivateKey) []byte {
	var k [deoxysii.KeySize]byte
	impl.DeriveSymmetricKey(k[:], peersPublicKey, privateKey)

	aead, err := deoxysii.New(k[:])
	api.Bzero(k[:])
	if err != nil {
		panic(err)
	}

	return aead.Seal(dst, nonce, plaintext, additionalData)
}

func (impl *boxImpl) Open(dst, nonce, plaintext, additionalData []byte, peersPublicKey *x25519.PublicKey, privateKey *x25519.PrivateKey) ([]byte, error) {
	var k [deoxysii.KeySize]byte
	impl.DeriveSymmetricKey(k[:], peersPublicKey, privateKey)

	aead, err := deoxysii.New(k[:])
	api.Bzero(k[:])
	if err != nil {
		panic(err)
	}

	return aead.Open(dst, nonce, plaintext, additionalData)
}
