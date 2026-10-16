package storage

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	dbAPI "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/pathbadger"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

func TestPruneNodeDB(t *testing.T) {
	ctx := context.Background()
	ns := common.NewTestNamespaceFromSeed([]byte("storage prune test ns"), 0)

	ndb, err := newTestNodeDB(t, ns)
	require.NoError(t, err)
	defer ndb.Close()

	lastRoot := newEmptyRoot(node.RootTypeState)
	addVersion := func(version uint64) node.Root {
		root := commitTestRoot(ctx, t, ndb, ns, lastRoot, version, node.RootTypeState, map[string]string{
			"key": "value " + strconv.FormatUint(version, 10),
		})
		require.NoError(t, ndb.Finalize([]node.Root{root}))
		lastRoot = root
		return root
	}

	for version := uint64(1); version <= 20; version++ {
		addVersion(version)
	}

	t.Run("prune", func(t *testing.T) {
		pruned, err := pruneBefore(ctx, ndb, 2)
		require.NoError(t, err)
		require.Equal(t, uint64(1), pruned)
		require.Equal(t, uint64(2), ndb.GetEarliestVersion())
	})

	t.Run("prune with retain version before earliest is no-op", func(t *testing.T) {
		pruned, err := pruneBefore(ctx, ndb, 1)
		require.NoError(t, err)
		require.EqualValues(t, 0, pruned)
		require.Equal(t, uint64(2), ndb.GetEarliestVersion())
	})

	t.Run("prune with periodic disk sync", func(t *testing.T) {
		wantEarliest := uint64(17)
		wantPruned := wantEarliest - ndb.GetEarliestVersion()
		pruned, err := pruneBefore(ctx, ndb, wantEarliest, withPruneDiskSyncInterval(2))
		require.NoError(t, err)
		require.Equal(t, wantPruned, pruned)
		require.Equal(t, wantEarliest, ndb.GetEarliestVersion())
	})
}

func TestPruneRuntimeHistory(t *testing.T) {
	ctx := t.Context()
	runtimeID := common.NewTestNamespaceFromSeed([]byte("runtime history prune test ns"), 0)

	h, err := history.New(runtimeID, t.TempDir(), history.NewNonePrunerFactory(), false)
	require.NoError(t, err, "New")
	defer h.Close()

	t.Run("empty", func(t *testing.T) {
		pruned, err := pruneRuntimeHistory(ctx, h, 10)
		require.NoError(t, err)
		require.EqualValues(t, 0, pruned)
	})

	// Commit blocks for rounds 0-19.
	blks := make([]*roothash.AnnotatedBlock, 20)
	for i := range blks {
		blk := &roothash.AnnotatedBlock{
			Height: int64(100 + i), // Height is different than round.
			Block:  block.NewGenesisBlock(runtimeID, 0),
		}
		blk.Block.Header.Round = uint64(i)
		blks[i] = blk
	}
	require.NoError(t, h.Commit(blks), "Commit")

	t.Run("prune", func(t *testing.T) {
		pruned, err := pruneRuntimeHistory(ctx, h, 1)
		require.NoError(t, err)
		require.EqualValues(t, 1, pruned)
	})

	t.Run("prune in batch", func(t *testing.T) {
		pruned, err := pruneRuntimeHistory(ctx, h, 17, withPruneRuntimeHistoryBatchSize(2))
		require.NoError(t, err)
		require.EqualValues(t, 16, pruned)
	})
}

func newTestNodeDB(t *testing.T, ns common.Namespace) (dbAPI.NodeDB, error) {
	t.Helper()

	return pathbadger.New(&dbAPI.Config{
		DB:        filepath.Join(t.TempDir()),
		Namespace: ns,
		NoFsync:   true,
	})
}

func commitTestRoot(
	ctx context.Context,
	t *testing.T,
	ndb dbAPI.NodeDB,
	ns common.Namespace,
	oldRoot node.Root,
	version uint64,
	rootType node.RootType,
	data map[string]string,
) node.Root {
	t.Helper()

	tree := mkvs.NewWithRoot(nil, ndb, oldRoot)
	defer tree.Close()

	for k, v := range data {
		err := tree.Insert(ctx, []byte(k), []byte(v))
		require.NoError(t, err)
	}

	_, rootHash, err := tree.Commit(ctx, ns, version)
	require.NoError(t, err)

	return node.Root{
		Namespace: ns,
		Version:   version,
		Type:      rootType,
		Hash:      rootHash,
	}
}

func newEmptyRoot(rootType node.RootType) node.Root {
	var root node.Root
	root.Empty()
	root.Type = rootType
	return root
}
