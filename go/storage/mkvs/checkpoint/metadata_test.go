package checkpoint

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	dbApi "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/pathbadger"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

func TestMetadataValidate(t *testing.T) {
	validRoot := node.Root{Namespace: testNs, Version: 1, Type: node.RootTypeIO}
	invalidRoot := node.Root{Namespace: testNs, Version: 1, Type: node.RootTypeInvalid}
	validChunks := []hash.Hash{{}}

	tests := []struct {
		name    string
		meta    *Metadata
		wantErr string
	}{
		{name: "nil", meta: nil, wantErr: "nil"},
		{name: "zero chunks", meta: &Metadata{Root: validRoot}, wantErr: "zero chunks"},
		{name: "invalid root type", meta: &Metadata{Root: invalidRoot, Chunks: validChunks}, wantErr: "invalid root type"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.ErrorContains(t, test.meta.Validate(), test.wantErr)
		})
	}
}

// TestMetadataValidateCpForEmptyState is a regression test asserting that a checkpoint created for
// an empty root produces at least one chunk, so that Validate passes.
func TestMetadataValidateCpForEmptyState(t *testing.T) {
	require := require.New(t)
	ctx := t.Context()

	ndb, err := pathbadger.New(&dbApi.Config{Namespace: testNs, MemoryOnly: true})
	require.NoError(err, "New")
	defer ndb.Close()

	tree := mkvs.New(nil, ndb, node.RootTypeIO)
	_, rootHash, err := tree.Commit(ctx, testNs, 1)
	require.NoError(err, "Commit")
	root := node.Root{Namespace: testNs, Version: 1, Type: node.RootTypeIO, Hash: rootHash}
	err = ndb.Finalize([]node.Root{root})
	require.NoError(err, "Finalize")

	fc, err := NewFileCreator(t.TempDir(), ndb)
	require.NoError(err, "NewFileCreator")
	cp, err := fc.CreateCheckpoint(ctx, root, 16*1024, 0)
	require.NoError(err, "CreateCheckpoint")

	require.NoError(cp.Validate())
}
