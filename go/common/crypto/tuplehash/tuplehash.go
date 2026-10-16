// Package tuplehash implements TupleHash from NIST SP 800-15.
package tuplehash

import (
	"crypto/sha3"
	"encoding/binary"
	"math"
	"math/bits"
)

var constN = []byte("TupleHash")

// Hasher is a TupleHash instance.
type Hasher struct {
	cShake     *sha3.SHAKE
	outputSize uint64
}

// Write writes the byte-encoded tuple b to the TupleHash.
func (h *Hasher) Write(b []byte) (int, error) {
	// Yes, panic is rude, but people are probably going to ignore the error
	// anyway, and this should never happen under any realistic scenario.
	l := uint64(len(b))
	if l > math.MaxUint64/8 {
		panic("common/crypto/tuplehash: invalid tuple size")
	}

	_, _ = h.cShake.Write(leftEncode(l * 8)) // in bits
	_, _ = h.cShake.Write(b)

	return int(l), nil
}

// Sum appends the current hash to b and returns the resulting slice.
// The underlying hash state is changed.
func (h *Hasher) Sum(b []byte) []byte {
	_, _ = h.cShake.Write(rightEncode(h.outputSize * 8)) // in bits
	digest := make([]byte, int(h.outputSize))
	_, _ = h.cShake.Read(digest)
	return append(b, digest...)
}

// New128 creates a new TupleHash128 instance with the specified output size
// (in bytes) and customization string.
func New128(outputSize int, customizationString []byte) *Hasher {
	return doNew(128, outputSize, customizationString)
}

// New256 creates a new TupleHash256 instance with the specified output size
// (in bytes) and customization string.
func New256(outputSize int, customizationString []byte) *Hasher {
	return doNew(256, outputSize, customizationString)
}

func doNew(securityStrength, outputSize int, customizationString []byte) *Hasher {
	// TODO: Once we switch to Go 1.17, assert outputSize <= math.MaxInt.
	oSize := uint64(outputSize)
	if oSize <= 0 || oSize > math.MaxUint64/8 {
		panic("common/crypto/tuplehash: invalid output size")
	}

	var cShake *sha3.SHAKE
	switch securityStrength {
	case 128:
		cShake = sha3.NewCSHAKE128(constN, customizationString)
	case 256:
		cShake = sha3.NewCSHAKE256(constN, customizationString)
	default:
		panic("common/crypto/tuplehash: invalid security strength")
	}

	return &Hasher{
		cShake:     cShake,
		outputSize: oSize,
	}
}

func leftEncode(x uint64) []byte {
	// Trim leading zero bytes, and prepend the length in bytes.
	if x <= 255 {
		// Special case, single byte.
		return []byte{1, byte(x)}
	}

	var b [9]byte
	binary.BigEndian.PutUint64(b[1:], x)
	nrZeroBytes := bits.LeadingZeros64(x) / 8
	b[nrZeroBytes] = byte(8 - nrZeroBytes) //nolint:gosec

	return b[nrZeroBytes:]
}

func rightEncode(x uint64) []byte {
	// Trim leading zero bytes, and append the length in bytes.
	if x <= 255 {
		// Special case, single byte.
		return []byte{byte(x), 1}
	}

	var b [9]byte
	binary.BigEndian.PutUint64(b[:], x)
	nrZeroBytes := bits.LeadingZeros64(x) / 8
	b[8] = byte(8 - nrZeroBytes) //nolint:gosec

	return b[nrZeroBytes:]
}
