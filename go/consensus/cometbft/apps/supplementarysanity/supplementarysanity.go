package supplementarysanity

import (
	"fmt"
	"math/rand"

	"github.com/cometbft/cometbft/abci/types"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
)

var (
	logger = logging.GetLogger("supplementarysanity")

	_ api.Application = (*supplementarySanityApplication)(nil)
)

// supplementarySanityApplication is a non-normative mux app that performs additional checks on the consensus state.
// It should not alter the CometBFT application state.
// It's okay for it to have this additional local state, because it won't affect anything that needs to be agreed upon
// in consensus.
type supplementarySanityApplication struct {
	state           api.ApplicationState
	interval        int64
	currentInterval int64
	checkHeight     int64
}

func (app *supplementarySanityApplication) Name() string {
	return AppName
}

func (app *supplementarySanityApplication) ID() uint8 {
	return AppID
}

func (app *supplementarySanityApplication) Methods() []transaction.MethodName {
	return nil
}

func (app *supplementarySanityApplication) Blessed() bool {
	return false
}

func (app *supplementarySanityApplication) Dependencies() []string {
	return []string{stakingState.AppName}
}

func (app *supplementarySanityApplication) QueryFactory() interface{} {
	return nil
}

func (app *supplementarySanityApplication) OnRegister(state api.ApplicationState, _ api.MessageDispatcher) {
	app.state = state
}

func (app *supplementarySanityApplication) OnCleanup() {
}

func (app *supplementarySanityApplication) ExecuteMessage(*api.Context, interface{}, interface{}) (interface{}, error) {
	return nil, fmt.Errorf("supplementarysanity: unexpected message")
}

func (app *supplementarySanityApplication) ExecuteTx(*api.Context, *transaction.Transaction) error {
	return fmt.Errorf("supplementarysanity: unexpected transaction")
}

func (app *supplementarySanityApplication) InitChain(*api.Context, types.RequestInitChain, *genesis.Document) error {
	return nil
}

func (app *supplementarySanityApplication) BeginBlock(*api.Context) error {
	return nil
}

func (app *supplementarySanityApplication) EndBlock(ctx *api.Context) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, app.endBlockImpl(ctx)
}

func (app *supplementarySanityApplication) endBlockImpl(ctx *api.Context) error {
	height := ctx.BlockHeight()

	if height == 1 {
		logger.Debug("skipping checks before InitChain")
		return nil
	}

	newInterval := height / app.interval
	if newInterval != app.currentInterval {
		min := height % app.interval
		offset := rand.Int63n(app.interval-min) + min
		app.currentInterval = newInterval
		app.checkHeight = newInterval*app.interval + offset
		logger.Debug("Entering new interval",
			"height", height,
			"check_height", app.checkHeight,
		)
	}

	if height != app.checkHeight {
		return nil
	}

	logger.Debug("checking this block", "height", height)

	now, err := app.state.GetEpoch(ctx, ctx.BlockHeight()+1)
	if err != nil {
		return fmt.Errorf("cometbft/supplementarysanity: failed to GetEpoch: %w", err)
	}
	for _, tt := range []struct {
		name    string
		checker func(ctx *api.Context, now beacon.EpochTime) error
	}{
		{"checkEpochTime", checkEpochTime},
		{"checkRegistry", checkRegistry},
		{"checkRootHash", checkRootHash},
		{"checkStaking", checkStaking},
		{"checkKeyManager", checkKeyManager},
		{"checkScheduler", checkScheduler},
		{"checkBeacon", checkBeacon},
		{"checkConsensus", checkConsensus},
		{"checkGovernance", checkGovernance},
		{"checkHalt", checkHalt},
		{"checkStakeClaims", checkStakeClaims},
	} {
		if err := tt.checker(ctx, now); err != nil {
			return fmt.Errorf("cometbft/supplementarysanity: check failed %s: %w", tt.name, err)
		}
	}

	return nil
}

func New(interval uint64) api.Application {
	return &supplementarySanityApplication{
		interval: int64(interval),
	}
}
