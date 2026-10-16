package checkpoint

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

// ChunkMetadata is chunk metadata.
type ChunkMetadata struct {
	Version uint16    `json:"version"`
	Root    node.Root `json:"root"`
	Index   uint64    `json:"index"`
	Digest  hash.Hash `json:"digest"`
}

// Metadata is checkpoint metadata.
type Metadata struct {
	Version uint16      `json:"version"`
	Root    node.Root   `json:"root"`
	Chunks  []hash.Hash `json:"chunks"`
}

// Validate checks that the metadata is structurally valid.
func (m *Metadata) Validate() error {
	if m == nil {
		return fmt.Errorf("nil metadata")
	}
	if m.Root.Type == node.RootTypeInvalid || m.Root.Type > node.RootTypeMax {
		return fmt.Errorf("invalid root type: %s", m.Root.Type)
	}
	if len(m.Chunks) == 0 {
		return fmt.Errorf("zero chunks")
	}
	return nil
}

// EncodedHash returns the encoded cryptographic hash of the checkpoint metadata.
func (m *Metadata) EncodedHash() hash.Hash {
	return hash.NewFrom(m)
}

// GetChunkMetadata returns the chunk metadata for the corresponding chunk.
func (m Metadata) GetChunkMetadata(idx uint64) (*ChunkMetadata, error) {
	if idx >= uint64(len(m.Chunks)) {
		return nil, ErrChunkNotFound
	}

	return &ChunkMetadata{
		Version: m.Version,
		Root:    m.Root,
		Index:   idx,
		Digest:  m.Chunks[int(idx)],
	}, nil
}
