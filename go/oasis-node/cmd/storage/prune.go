package storage

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/store"
	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/config"
	cmtConfig "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/config"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	"github.com/oasisprotocol/oasis-core/go/runtime/registry"
	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
)

func newPruneCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prune",
		Args:  cobra.NoArgs,
		Short: "trigger pruning of all databases",
		PreRunE: func(_ *cobra.Command, args []string) error {
			if err := cmdCommon.Init(); err != nil {
				cmdCommon.EarlyLogAndExit(err)
			}

			running, err := cmdCommon.IsNodeRunning()
			if err != nil {
				return fmt.Errorf("failed to ensure the node is not running: %w", err)
			}
			if running {
				return fmt.Errorf("pruning can only be done when the node is not running")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			runtimes, err := registry.GetConfiguredRuntimeIDs()
			if err != nil {
				return fmt.Errorf("failed to get configured runtimes: %w", err)
			}

			logger.Info("Starting databases pruning. This may take a while...")

			dataDir := cmdCommon.DataDir()
			ctx := cmd.Context()

			// Consensus pruning
			if config.GlobalConfig.Consensus.Prune.Strategy == cmtConfig.PruneStrategyNone {
				logger.Info("skipping consensus pruning since disabled in the config")
			} else if err := pruneConsensusDBs(
				ctx,
				dataDir,
				config.GlobalConfig.Consensus.Prune.NumKept,
				runtimes,
			); err != nil {
				return fmt.Errorf("failed to prune consensus databases: %w", err)
			}

			// Runtime pruning
			if len(runtimes) == 0 {
				return nil
			}
			if !config.GlobalConfig.Runtime.Prune.IsEnabled() {
				logger.Info("skipping runtime pruning since disabled in the config")
				return nil
			}
			for _, rt := range runtimes {
				if err := pruneRuntimeDBs(
					ctx,
					dataDir,
					rt,
					config.GlobalConfig.Runtime.Prune.NumKept,
				); err != nil {
					return fmt.Errorf("failed to prune runtime databases (runtime ID: %s): %w", rt, err)
				}
			}

			logger.Info("pruning of all databases successful")

			return nil
		},
	}
	return cmd
}

func pruneConsensusDBs(ctx context.Context, dataDir string, numKept uint64, runtimes []common.Namespace) error {
	ndb, close, err := openConsensusNodeDB(dataDir)
	if err != nil {
		return fmt.Errorf("failed to open NodeDB: %w", err)
	}
	defer close()

	latest, ok := ndb.GetLatestVersion()
	if !ok {
		logger.Info("skipping consensus pruning as state db is empty")
		return nil
	}

	if latest < numKept {
		logger.Info("skipping consensus pruning as the latest version is smaller than the number of versions to keep")
		return nil
	}

	// In case of configured runtimes, do not prune past the earliest reindexed
	// consensus height, so that light history can be populated correctly.
	minReindexed, err := minReindexedHeight(dataDir, runtimes)
	if err != nil {
		return fmt.Errorf("failed to fetch earliest reindexed consensus height: %w", err)
	}

	retainHeight := min(
		latest-numKept, // underflow not possible due to if above.
		uint64(minReindexed),
	)

	logger.Info("pruning consensus state DB", "retain_height", retainHeight)
	pruned, err := pruneBefore(ctx, ndb, retainHeight)
	if err != nil {
		return fmt.Errorf("failed to prune consensus state DB: %w", err)
	}
	logger.Info("pruning of consensus state DB successful", "pruned", pruned)

	if err := pruneCometDBs(ctx, dataDir, int64(retainHeight)); err != nil {
		return fmt.Errorf("failed to prune CometBFT managed databases: %w", err)
	}

	logger.Info("pruning of consensus databases successful")
	return nil
}

type pruneOption func(*pruneOptions)

type pruneOptions struct {
	diskSyncInterval uint64
}

func withPruneDiskSyncInterval(interval uint64) pruneOption {
	return func(opts *pruneOptions) {
		opts.diskSyncInterval = interval
	}
}

func pruneBefore(ctx context.Context, ndb db.NodeDB, version uint64, options ...pruneOption) (uint64, error) {
	opts := pruneOptions{
		diskSyncInterval: 10_000,
	}
	for _, option := range options {
		option(&opts)
	}

	earliest := ndb.GetEarliestVersion()

	if version <= earliest {
		logger.Info("db state already pruned", "earliest", earliest, "version", version)
		return 0, nil
	}

	logger.Info("pruning node DB", "earliest", earliest, "version", version)
	var pruned uint64
	for h := earliest; h < version; h++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if err := ndb.Prune(h); err != nil {
			return 0, fmt.Errorf("failed to prune version %d: %w", h, err)
		}
		pruned++

		if opts.diskSyncInterval != 0 && h%opts.diskSyncInterval == 0 { // periodically sync to disk
			if err := ndb.Sync(); err != nil {
				return 0, fmt.Errorf("failed to sync NodeDB: %w", err)
			}
			logger.Debug("forcing NodeDB disk sync during pruning", "version", h)
		}
	}

	if err := ndb.Sync(); err != nil {
		return 0, fmt.Errorf("failed to sync NodeDB: %w", err)
	}

	return pruned, nil
}

// minReindexedHeight returns the smallest consensus height reindexed by any
// of the configured runtimes.
//
// In case of no configured runtimes it returns max int64.
func minReindexedHeight(dataDir string, runtimes []common.Namespace) (int64, error) {
	fetchLastReindexedHeight := func(runtimeID common.Namespace) (int64, error) {
		history, err := openRuntimeLightHistory(dataDir, runtimeID)
		if err != nil {
			return 0, fmt.Errorf("failed to open runtime light history: %w", err)
		}
		defer history.Close()

		h, err := history.LastConsensusHeight()
		if err != nil {
			return 0, fmt.Errorf("failed to get last consensus height: %w", err)
		}

		return h, nil
	}

	var minH int64 = math.MaxInt64
	for _, rt := range runtimes {
		h, err := fetchLastReindexedHeight(rt)
		if err != nil {
			return 0, fmt.Errorf("failed to fetch last reindexed height for %s: %w", rt, err)
		}

		if h < minH {
			minH = h
		}
	}

	return minH, nil
}

func pruneCometDBs(ctx context.Context, dataDir string, retainHeight int64) error {
	blockstore, err := openConsensusBlockstore(dataDir)
	if err != nil {
		return fmt.Errorf("failed to open consensus blockstore: %w", err)
	}
	defer blockstore.Close()

	state, err := openConsensusStatestore(dataDir)
	if err != nil {
		return fmt.Errorf("failed to open consensus state store: %w", err)
	}
	defer state.Close()

	logger.Info("pruning block and state store", "retain_height", retainHeight)

	const cometPruneBatchSize int64 = 10_000
	var totalPruned uint64
	for pruneUntil := blockstore.Base(); pruneUntil < retainHeight; {
		if err = ctx.Err(); err != nil {
			return err
		}

		pruneUntil = min(pruneUntil+cometPruneBatchSize, retainHeight)

		pruned, err := pruneBlocks(blockstore, state, pruneUntil)
		if err != nil {
			return fmt.Errorf("failed to prune block and state store: %w", err)
		}
		totalPruned += pruned
	}

	logger.Info("successfully pruned block and state store", "pruned", totalPruned)

	return nil
}

// pruneBlocks mimics the upstream pruning logic from CometBFT
// (see https://github.com/oasisprotocol/cometbft/blob/653c9a0c95ac0f91a0c8c11efb9aa21c98407af6/state/execution.go#L655):
// 1. Get the base from the blockstore
// 2. Prune blockstore
// 3. Prune statestore
//
// This ordering is problematic: if the blockstore pruning succeeds (updating the base) but
// state DB pruning fails or is interrupted, a subsequent pruning run will skip already
// pruned blocks while leaving part of the state DB unpruned.
//
// Best way to mitigate the size of stale state (if it happens, very unlikely) is to prune in small batches.
func pruneBlocks(blockstore *store.BlockStore, statestore state.Store, retainHeight int64) (uint64, error) {
	base := blockstore.Base()
	if retainHeight <= base {
		logger.Info("blockstore and state db already pruned")
		return 0, nil
	}

	logger.Debug("pruning consensus blockstore", "base", base, "retain_height", retainHeight)
	pruned, err := blockstore.PruneBlocks(retainHeight)
	if err != nil {
		return 0, fmt.Errorf("failed to prune blocks (retain height: %d): %w", retainHeight, err)
	}

	logger.Debug("pruning consensus states", "base", base, "retain_height", retainHeight)
	if err := statestore.PruneStates(base, retainHeight); err != nil {
		return 0, fmt.Errorf("failed to prune state db (start: %d, end: %d): %w", base, retainHeight, err)
	}

	return pruned, nil
}

func pruneRuntimeDBs(ctx context.Context, dataDir string, runtimeID common.Namespace, numKept uint64) error {
	logger := logger.With("runtime_id", runtimeID)

	ndb, err := openRuntimeStateDB(dataDir, runtimeID)
	if err != nil {
		return fmt.Errorf("failed to open runtime state DB: %w", err)
	}
	defer ndb.Close()
	latest, ok := ndb.GetLatestVersion()
	if !ok {
		logger.Info("skipping runtime pruning as state DB is empty")
		return nil
	}

	if latest < numKept {
		logger.Info("skipping runtime pruning as the latest version is smaller than the number of versions to keep")
		return nil
	}

	// By calculating retain round from the runtime state DB latest round,
	// we ensure light history is never pruned past the latest synced runtime
	// round.
	retainRound := latest - numKept

	// Prune light history before state DB, since node expects this order
	// of pruning.
	logger.Info("pruning runtime history", "retain_round", retainRound)
	history, err := openRuntimeLightHistory(dataDir, runtimeID)
	if err != nil {
		return fmt.Errorf("failed to open runtime light history: %w", err)
	}
	defer history.Close()
	pruned, err := pruneRuntimeHistory(ctx, history, retainRound)
	if err != nil {
		return fmt.Errorf("failed to prune runtime history before round %d: %w", retainRound, err)
	}
	logger.Info("pruning of runtime history successful", "pruned", pruned)

	logger.Info("pruning runtime state DB", "retain_round", retainRound)
	pruned, err = pruneBefore(ctx, ndb, retainRound)
	if err != nil {
		return fmt.Errorf("failed to prune nodeDB before round %d: %w", retainRound, err)
	}
	logger.Info("pruning of runtime state DB successful", "pruned", pruned)

	return nil
}

type pruneRuntimeHistoryOption func(*pruneRuntimeHistoryOptions)

type pruneRuntimeHistoryOptions struct {
	batchSize uint64
}

func withPruneRuntimeHistoryBatchSize(batchSize uint64) pruneRuntimeHistoryOption {
	return func(opts *pruneRuntimeHistoryOptions) {
		opts.batchSize = batchSize
	}
}

func pruneRuntimeHistory(ctx context.Context, history history.History, retainRound uint64, options ...pruneRuntimeHistoryOption) (uint64, error) {
	opts := pruneRuntimeHistoryOptions{
		batchSize: 10_000,
	}
	for _, option := range options {
		option(&opts)
	}

	earliest, err := history.GetEarliestBlock(ctx)
	switch {
	case err == nil:
	case errors.Is(err, roothash.ErrNotFound): // empty
		return 0, nil
	default:
		return 0, fmt.Errorf("failed to get earliest runtime block: %w", err)
	}

	var totalPruned uint64
	for pruneUntil := earliest.Header.Round; pruneUntil < retainRound; {
		logger.Debug("pruning runtime history", "prune_until", pruneUntil)
		if err = ctx.Err(); err != nil {
			return 0, err
		}

		pruneUntil = min(pruneUntil+opts.batchSize, retainRound)

		pruned, err := history.PruneBefore(pruneUntil)
		if err != nil {
			return 0, fmt.Errorf("failed to prune runtime history before round %d: %w", pruneUntil, err)
		}
		totalPruned += pruned
		logger.Debug("pruned runtime history", "pruned", pruned)
	}

	return totalPruned, nil
}
