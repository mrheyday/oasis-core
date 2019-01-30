// Package roothash implements the roothash application.
package roothash

import (
	"bytes"
	"encoding/hex"
	"time"

	"github.com/pkg/errors"
	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"
	"golang.org/x/net/context"
	"google.golang.org/grpc/status"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	"github.com/oasislabs/ekiden/go/tendermint/api"
	registryapp "github.com/oasislabs/ekiden/go/tendermint/apps/registry"
)

var (
	errNoSuchRuntime = errors.New("tendermint/roothash: no such runtime")
	errNoRound       = errors.New("tendermint/roothash: no round in progress")

	_ abci.Application = (*rootHashApplication)(nil)
)

type timerContext struct {
	ID    signature.PublicKey `codec:"id"`
	Round uint64              `codec:"round"`
}

func (ctx *timerContext) MarshalCBOR() []byte {
	return cbor.Marshal(ctx)
}

func (ctx *timerContext) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, ctx)
}

type rootHashApplication struct {
	logger *logging.Logger
	state  *abci.ApplicationState

	timeSource epochtime.BlockBackend
	scheduler  scheduler.BlockBackend
	storage    storage.Backend

	// The old and busted way of importing genesis state.
	// TODO: Remove once tooling for the new way is present.
	cfgGenesisBlocks map[signature.MapKey]*block.Block

	roundTimeout time.Duration
}

func (app *rootHashApplication) Name() string {
	return api.RootHashAppName
}

func (app *rootHashApplication) TransactionTag() byte {
	return api.RootHashTransactionTag
}

func (app *rootHashApplication) Blessed() bool {
	return false
}

func (app *rootHashApplication) OnRegister(state *abci.ApplicationState, queryRouter abci.QueryRouter) {
	app.state = state

	// Register query handlers.
	queryRouter.AddRoute(api.QueryRootHashGetLatestBlock, api.QueryGetLatestBlock{}, app.queryGetLatestBlock)
}

func (app *rootHashApplication) OnCleanup() {
}

func (app *rootHashApplication) SetOption(request types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *rootHashApplication) GetState(height int64) (interface{}, error) {
	return NewImmutableState(app.state, height)
}

func (app *rootHashApplication) queryGetLatestBlock(s interface{}, r interface{}) ([]byte, error) {
	request := r.(*api.QueryGetLatestBlock)
	state := s.(*ImmutableState)

	runtime, err := state.GetRuntimeState(request.ID)
	if err != nil {
		return nil, err
	}
	if runtime == nil {
		return nil, errNoSuchRuntime
	}

	block := runtime.CurrentBlock.MarshalCBOR()

	return block, nil
}

func (app *rootHashApplication) CheckTx(ctx *abci.Context, tx []byte) error {
	request := &api.TxRootHash{}
	if err := cbor.Unmarshal(tx, request); err != nil {
		app.logger.Error("CheckTx: failed to unmarshal",
			"tx", hex.EncodeToString(tx),
		)
		return errors.Wrap(err, "roothash: failed to unmarshal")
	}

	if err := app.executeTx(ctx, app.state.CheckTxTree(), request); err != nil {
		return err
	}

	return nil
}

func (app *rootHashApplication) ForeignCheckTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *rootHashApplication) InitChain(ctx *abci.Context, request types.RequestInitChain) types.ResponseInitChain {
	var st api.GenesisRootHashState
	if err := abci.UnmarshalGenesisAppState(request, app, &st); err != nil {
		app.logger.Error("InitChain: failed to unmarshal genesis state",
			"err", err,
		)
		panic("roothash: invalid genesis state")
	}

	if len(st.Blocks) != 0 {
		// XXX: Either deprecate the command line option, or figure
		// out a nice way to merge the two.  Probably the former.
		if len(app.cfgGenesisBlocks) != 0 {
			app.logger.Error("InitChain: genesis blocks already exist")
			panic("roothash: genesis blocks already exist")
		}
	}

	// The per-runtime roothash state is done primarily via DeliverTx, but
	// also needs to be done here since the genesis state can have runtime
	// registrations.
	//
	// Note: This could use the genesis state, but the registry has already
	// carved out it's entries by this point.

	tree := app.state.DeliverTxTree()

	regState := registryapp.NewMutableState(tree)
	runtimes, _ := regState.GetRuntimes()
	for _, v := range runtimes {
		app.logger.Info("InitChain: allocating per-runtime state",
			"runtime", v.ID,
		)
		app.onNewRuntime(ctx, tree, v, &st)
	}

	return types.ResponseInitChain{}
}

func (app *rootHashApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) {
	// Only perform checks on epoch changes.
	if changed, _ := app.state.EpochChanged(app.timeSource); changed {
		app.onEpochChange(ctx)
	}
}

func (app *rootHashApplication) onEpochChange(ctx *abci.Context) { // nolint: gocyclo
	tree := app.state.DeliverTxTree()
	state := NewMutableState(tree)

	// Query the updated runtime list.
	regState := registryapp.NewMutableState(tree)
	runtimes, _ := regState.GetRuntimes()
	newDescriptors := make(map[signature.MapKey]*registry.Runtime)
	for _, v := range runtimes {
		newDescriptors[v.ID.ToMapKey()] = v
	}

	for _, runtimeState := range state.GetRuntimes() {
		rtID := runtimeState.Runtime.ID

		committees, err := app.scheduler.GetBlockCommittees(context.Background(), rtID, app.state.BlockHeight())
		if err != nil {
			app.logger.Error("checkCommittees: failed to get committees from scheduler",
				"err", err,
				"runtime", rtID,
			)
			continue
		}

		var committee *scheduler.Committee
		for _, c := range committees {
			if c.Kind == scheduler.Compute {
				committee = c
				break
			}
		}
		if committee == nil {
			app.logger.Error("checkCommittees: scheduler did not give us a compute committee",
				"runtime", rtID,
			)
			continue
		}

		app.logger.Debug("checkCommittees: updating committee for runtime",
			"runtime", rtID,
		)

		// If the committee is the "same", ignore this.
		//
		// TODO: Use a better check to allow for things like rescheduling.
		round := runtimeState.Round
		if round != nil && round.RoundState.Committee.ValidFor == committee.ValidFor {
			app.logger.Debug("checkCommittees: duplicate committee or reschedule, ignoring",
				"runtime", rtID,
				"epoch", committee.ValidFor,
			)
			mk := rtID.ToMapKey()
			if _, ok := newDescriptors[mk]; ok {
				delete(newDescriptors, rtID.ToMapKey())
			}
			continue
		}

		// Transition the round.
		blk := runtimeState.CurrentBlock
		blockNr, _ := blk.Header.Round.ToU64()

		app.logger.Debug("checkCommittees: new committee, transitioning round",
			"runtime", rtID,
			"epoch", committee.ValidFor,
			"round", blockNr,
		)

		runtimeState.Timer.Stop(ctx)
		runtimeState.Round = newRound(committee, blk)

		// Emit an empty epoch transition block in the new round. This is required so that
		// the clients can be sure what state is final when an epoch transition occurs.
		app.emitEmptyBlock(ctx, runtimeState, block.EpochTransition)

		mk := rtID.ToMapKey()
		if rt, ok := newDescriptors[mk]; ok {
			// Update the runtime descriptor to the latest per-epoch value.
			runtimeState.Runtime = rt
			delete(newDescriptors, mk)
		}

		state.UpdateRuntimeState(runtimeState)
	}

	// Just because a runtime didn't have committees, it doesn't mean that
	// it's state does not need to be updated. Do so now where possible.
	for _, v := range newDescriptors {
		runtimeState, err := state.GetRuntimeState(v.ID)
		if err != nil {
			app.logger.Warn("onEpochChange: unknown runtime in update pass",
				"runtime", v,
			)
			continue
		}

		runtimeState.Runtime = v
		state.UpdateRuntimeState(runtimeState)
	}
}

func (app *rootHashApplication) emitEmptyBlock(ctx *abci.Context, runtime *RuntimeState, hdrType block.HeaderType) {
	blk := block.NewEmptyBlock(runtime.CurrentBlock, uint64(ctx.Now().Unix()), hdrType)
	runtime.Round.populateFinalizedBlock(blk)

	runtime.CurrentBlock = blk

	roundNr, _ := blk.Header.Round.ToU64()

	ctx.EmitTag(api.TagRootHashUpdate, api.TagRootHashUpdateValue)
	tagV := api.ValueRootHashFinalized{
		ID:    runtime.Runtime.ID,
		Round: roundNr,
	}
	ctx.EmitTag(api.TagRootHashFinalized, tagV.MarshalCBOR())
}

func (app *rootHashApplication) DeliverTx(ctx *abci.Context, tx []byte) error {
	request := &api.TxRootHash{}
	if err := cbor.Unmarshal(tx, request); err != nil {
		app.logger.Error("DeliverTx: failed to unmarshal",
			"tx", hex.EncodeToString(tx),
		)
		return errors.Wrap(err, "roothash: failed to unmarshal")
	}

	return app.executeTx(ctx, app.state.DeliverTxTree(), request)
}

func (app *rootHashApplication) ForeignDeliverTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	var st *api.GenesisRootHashState
	ensureGenesis := func() error {
		var err error

		if st == nil {
			st = new(api.GenesisRootHashState)
			if err = app.state.Genesis().UnmarshalAppState(app.Name(), st); err != nil {
				st = nil
			}
		}

		return err
	}

	switch other.Name() {
	case api.RegistryAppName:
		for _, pair := range ctx.Tags() {
			if bytes.Equal(pair.GetKey(), api.TagRegistryRuntimeRegistered) {
				runtime := pair.GetValue()

				app.logger.Debug("ForeignDeliverTx: new runtime",
					"runtime", hex.EncodeToString(runtime),
				)

				tree := app.state.DeliverTxTree()

				// New runtime has been registered, create its roothash state.
				regState := registryapp.NewMutableState(tree)
				rt, err := regState.GetRuntime(runtime)
				if err != nil {
					return errors.Wrap(err, "roothash: failed to fetch new runtime")
				}

				if err = ensureGenesis(); err != nil {
					return errors.Wrap(err, "roothash: failed to fetch genesis blocks")
				}

				app.onNewRuntime(ctx, tree, rt, st)
			}
		}
	}

	return nil
}

func (app *rootHashApplication) onNewRuntime(ctx *abci.Context, tree *iavl.MutableTree, runtime *registry.Runtime, genesis *api.GenesisRootHashState) {
	state := NewMutableState(tree)

	// Check if state already exists for the given runtime.
	runtimeState, _ := state.GetRuntimeState(runtime.ID)
	if runtimeState != nil {
		// Do not propagate the error as this would fail the transaction.
		app.logger.Warn("onNewRuntime: state for runtime already exists",
			"runtime", runtime,
		)
		return
	}

	// Create genesis block.
	var genesisBlock *block.Block
	if app.cfgGenesisBlocks != nil {
		genesisBlock = app.cfgGenesisBlocks[runtime.ID.ToMapKey()]
	} else {
		genesisBlock = genesis.Blocks[runtime.ID.ToMapKey()]
	}
	if genesisBlock == nil {
		now := ctx.Now().Unix()
		genesisBlock = block.NewGenesisBlock(runtime.ID, uint64(now))
	}

	roundNr, _ := genesisBlock.Header.Round.ToU64()

	// Create new state containing the genesis block.
	timerCtx := &timerContext{ID: runtime.ID}
	state.UpdateRuntimeState(&RuntimeState{
		Runtime:      runtime,
		CurrentBlock: genesisBlock,
		Timer:        *abci.NewTimer(ctx, app, "round-"+runtime.ID.String(), timerCtx.MarshalCBOR()),
	})

	app.logger.Debug("onNewRuntime: created genesis state for runtime",
		"runtime", runtime,
	)

	// This transaction now also includes a new block for the given runtime.
	id, _ := runtime.ID.MarshalBinary()
	ctx.EmitTag(api.TagRootHashUpdate, api.TagRootHashUpdateValue)
	tagV := api.ValueRootHashFinalized{
		ID:    id,
		Round: roundNr,
	}
	ctx.EmitTag(api.TagRootHashFinalized, tagV.MarshalCBOR())
}

func (app *rootHashApplication) EndBlock(request types.RequestEndBlock) types.ResponseEndBlock {
	return types.ResponseEndBlock{}
}

func (app *rootHashApplication) FireTimer(ctx *abci.Context, timer *abci.Timer) {
	var tCtx timerContext
	if err := tCtx.UnmarshalCBOR(timer.Data()); err != nil {
		panic(err)
	}

	tree := app.state.DeliverTxTree()
	state := NewMutableState(tree)
	runtimeState, err := state.GetRuntimeState(tCtx.ID)
	if err != nil {
		app.logger.Error("FireTimer: failed to get state associated with timer",
			"err", err,
		)
		panic(err)
	}
	runtime := runtimeState.Runtime

	latestBlock := runtimeState.CurrentBlock
	if blockNr, _ := latestBlock.Header.Round.ToU64(); blockNr != tCtx.Round {
		// Note: This should NEVER happen, but it does and causes massive
		// problems (#1047).
		app.logger.Error("FireTimer: spurious timeout detected",
			"runtime", tCtx.ID,
			"timer_round", tCtx.Round,
			"current_round", blockNr,
		)

		timer.Stop(ctx)

		// WARNING: `timer` != runtimeState.Timer, while the ID shouldn't
		// change and the difference in structs should be harmless, there
		// is nothing lost with being extra defensive.

		var rsCtx timerContext
		if err := rsCtx.UnmarshalCBOR(runtimeState.Timer.Data()); err != nil {
			app.logger.Error("FireTimer: Failed to unmarshal runtime state timer",
				"err", err,
			)
			return
		}

		app.logger.Error("FireTimer: runtime state timer",
			"runtime", rsCtx.ID,
			"timer_round", rsCtx.Round,
		)

		runtimeState.Timer.Stop(ctx)
		state.UpdateRuntimeState(runtimeState)

		return
	}

	app.logger.Warn("FireTimer: round timeout expired, forcing finalization",
		"runtime", tCtx.ID,
		"timer_round", tCtx.Round,
	)

	defer state.UpdateRuntimeState(runtimeState)
	runtimeState.Round.DidTimeout = true
	app.tryFinalize(ctx, runtime, runtimeState, true)
}

func (app *rootHashApplication) executeTx(
	ctx *abci.Context,
	tree *iavl.MutableTree,
	tx *api.TxRootHash,
) error {
	state := NewMutableState(tree)

	if tx.TxCommit != nil {
		return app.commit(ctx, state, tx.TxCommit.ID, &tx.TxCommit.Commitment)
	}
	return roothash.ErrInvalidArgument
}

func (app *rootHashApplication) commit(
	ctx *abci.Context,
	state *MutableState,
	id signature.PublicKey,
	commit *roothash.OpaqueCommitment,
) error {
	runtimeState, err := state.GetRuntimeState(id)
	if err != nil {
		return errors.Wrap(err, "roothash: failed to fetch runtime state")
	}
	if runtimeState == nil {
		return errNoSuchRuntime
	}
	runtime := runtimeState.Runtime

	var c commitment.Commitment
	if err = c.FromOpaqueCommitment(commit); err != nil {
		return errors.Wrap(err, "roothash: failed to unmarshal commitment")
	}

	if ctx.IsCheckOnly() {
		// If we are within CheckTx then we cannot do any further checks as epoch
		// transitions are only handled in BeginBlock.
		return nil
	}

	if runtimeState.Round == nil {
		app.logger.Error("commit recevied when no round in progress",
			"err", errNoRound,
		)
		return errNoRound
	}

	latestBlock := runtimeState.CurrentBlock
	blockNr, _ := latestBlock.Header.Round.ToU64()

	defer state.UpdateRuntimeState(runtimeState)

	// If the round was finalized, transition.
	if runtimeState.Round.RoundState.CurrentBlock.Header.Round != latestBlock.Header.Round {
		app.logger.Debug("round was finalized, transitioning round",
			"round", blockNr,
		)

		runtimeState.Round = newRound(runtimeState.Round.RoundState.Committee, latestBlock)
	}

	// Add the commitment.
	if err = runtimeState.Round.addCommitment(app.storage, &c); err != nil {
		app.logger.Error("failed to add commitment to round",
			"err", err,
			"round", blockNr,
		)

		// HACK/#1380: Transient storage failures result in non-deterministic behavior.
		if _, ok := status.FromError(err); ok {
			app.logger.Error("BUG: gRPC failure, CRASHING TO PROTECT STATE",
				"err", err,
			)
			panic("BUG: gRPC failure, CRASHING TO PROTECT STATE: " + err.Error())
		}

		return err
	}

	// Try to finalize round.
	app.tryFinalize(ctx, runtime, runtimeState, false)

	return nil
}

func (app *rootHashApplication) tryFinalize(
	ctx *abci.Context,
	runtime *registry.Runtime,
	runtimeState *RuntimeState,
	forced bool,
) { // nolint: gocyclo
	latestBlock := runtimeState.CurrentBlock
	blockNr, _ := latestBlock.Header.Round.ToU64()

	var rearmTimer bool
	defer func() {
		// Note: Unlike the Rust code, this pushes back the timer
		// each time forward progress is made.

		switch rearmTimer {
		case true: // (Re-)arm timer.
			app.logger.Debug("(re-)arming round timeout")

			timerCtx := &timerContext{
				ID:    runtime.ID,
				Round: blockNr,
			}
			runtimeState.Timer.Reset(ctx, app.roundTimeout, timerCtx.MarshalCBOR())
		case false: // Disarm timer.
			app.logger.Debug("disarming round timeout")
			runtimeState.Timer.Stop(ctx)
		}
	}()

	state := runtimeState.Round.RoundState.State
	id, _ := runtime.ID.MarshalBinary()

	if state == stateFinalized {
		app.logger.Error("attempted to finalize when block already finalized",
			"round", blockNr,
		)
		return
	}

	blk, err := runtimeState.Round.tryFinalize(ctx, runtime)
	switch err {
	case nil:
		// Round has been finalized.
		app.logger.Debug("finalized round",
			"round", blockNr,
		)

		runtimeState.CurrentBlock = blk

		roundNr, _ := blk.Header.Round.ToU64()

		ctx.EmitTag(api.TagRootHashUpdate, api.TagRootHashUpdateValue)
		tagV := api.ValueRootHashFinalized{
			ID:    id,
			Round: roundNr,
		}
		ctx.EmitTag(api.TagRootHashFinalized, tagV.MarshalCBOR())
		return
	case errStillWaiting:
		if forced {
			if state == stateDiscrepancyWaitingCommitments {
				// This was a forced finalization call due to timeout,
				// and the round was in the discrepancy state.  Give up.
				app.logger.Error("failed to finalize discrepancy committee on timeout",
					"round", blockNr,
				)
				break
			}

			// This is the fast path and the round timer expired.
			//
			// Transition to the discrepancy state so the backup workers
			// process the round, assuming that is is possible to do so.
			app.logger.Error("failed to finalize committee on timeout",
				"round", blockNr,
			)
			err = runtimeState.Round.forceBackupTransition()
			break
		}

		app.logger.Debug("insufficient commitments for finality, waiting",
			"round", blockNr,
		)

		rearmTimer = true
		return
	default:
	}

	if dErr, ok := (err).(errDiscrepancyDetected); ok {
		inputHash := hash.Hash(dErr)

		app.logger.Warn("discrepancy detected",
			"round", blockNr,
			"input_hash", inputHash,
		)

		ctx.EmitTag(api.TagRootHashUpdate, api.TagRootHashUpdateValue)
		tagV := api.ValueRootHashDiscrepancyDetected{
			ID: id,
			Event: roothash.DiscrepancyDetectedEvent{
				BatchHash:   &inputHash,
				BlockHeader: &latestBlock.Header,
			},
		}
		ctx.EmitTag(api.TagRootHashDiscrepancyDetected, tagV.MarshalCBOR())

		// Re-arm the timer.  The rust code waits till the first discrepancy
		// commit to do this, but there is 0 guarantee that said commit will
		// come.
		rearmTimer = true
		return
	}

	// Something else went wrong, emit empty error block.
	app.logger.Error("worker: round failed",
		"round", blockNr,
		"err", err,
	)

	app.emitEmptyBlock(ctx, runtimeState, block.RoundFailed)
}

// New constructs a new roothash application instance.
func New(
	timeSource epochtime.BlockBackend,
	scheduler scheduler.BlockBackend,
	storage storage.Backend,
	genesisBlocks map[signature.MapKey]*block.Block,
	roundTimeout time.Duration,
) abci.Application {
	return &rootHashApplication{
		logger:           logging.GetLogger("tendermint/roothash"),
		timeSource:       timeSource,
		scheduler:        scheduler,
		storage:          storage,
		cfgGenesisBlocks: genesisBlocks,
		roundTimeout:     roundTimeout,
	}
}
