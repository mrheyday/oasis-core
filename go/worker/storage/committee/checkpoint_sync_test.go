package committee

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/checkpointsync"
)

func TestSortCheckpoints(t *testing.T) {
	cp1 := &checkpointsync.Checkpoint{
		Metadata: &checkpoint.Metadata{
			Root: node.Root{
				Version: 2,
			},
		},
		Peers: []rpc.PeerFeedback{rpc.NewNopPeerFeedback(), rpc.NewNopPeerFeedback()},
	}
	cp2 := &checkpointsync.Checkpoint{
		Metadata: &checkpoint.Metadata{
			Root: node.Root{
				Version: 2,
			},
		},
		Peers: []rpc.PeerFeedback{rpc.NewNopPeerFeedback()},
	}
	cp3 := &checkpointsync.Checkpoint{
		Metadata: &checkpoint.Metadata{
			Root: node.Root{
				Version: 1,
			},
		},
		Peers: []rpc.PeerFeedback{rpc.NewNopPeerFeedback(), rpc.NewNopPeerFeedback()},
	}
	cp4 := &checkpointsync.Checkpoint{
		Metadata: &checkpoint.Metadata{
			Root: node.Root{
				Version: 1,
			},
		},
		Peers: []rpc.PeerFeedback{rpc.NewNopPeerFeedback()},
	}

	s := []*checkpointsync.Checkpoint{cp2, cp3, cp4, cp1}

	sortCheckpoints(s)

	assert.Equal(t, s, []*checkpointsync.Checkpoint{cp1, cp2, cp3, cp4})
}

func TestValidateCheckpoint(t *testing.T) {
	runtimeID := common.NewTestNamespaceFromSeed([]byte("test namespace"), 0)
	blk := block.NewGenesisBlock(runtimeID, 0)

	validRoot := blk.Header.StorageRootState()

	wrongNamespaceRoot := validRoot
	wrongNamespaceRoot.Namespace = common.NewTestNamespaceFromSeed([]byte("test namespace invalid"), 0)

	unexpectedRoot := validRoot
	unexpectedRoot.Hash[0] ^= 0xff // flip bits in the first byte so that hashes don't match.

	for _, tc := range []struct {
		name      string
		root      node.Root
		errPrefix string
	}{
		{
			name: "valid root",
			root: validRoot,
		},
		{
			name:      "namespace mismatch",
			root:      wrongNamespaceRoot,
			errPrefix: "namespace mismatch:",
		},
		{
			name:      "unexpected root",
			root:      unexpectedRoot,
			errPrefix: "checkpoint metadata with unexpected root",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := &checkpointsync.Checkpoint{
				Metadata: &checkpoint.Metadata{
					Root: tc.root,
				},
			}

			err := validateCheckpoint(cp, blk)
			if tc.errPrefix == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tc.errPrefix)
		})
	}
}
