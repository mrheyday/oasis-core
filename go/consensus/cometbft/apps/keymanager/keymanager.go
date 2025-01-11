package keymanager

import (
	"fmt"

	"github.com/cometbft/cometbft/abci/types"

	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/secrets"
	registryapp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

type keymanagerApplication struct {
	state tmapi.ApplicationState

	exts         []tmapi.Extension
	methods      []transaction.MethodName
	extsByMethod map[transaction.MethodName]tmapi.Extension
}

// Name implements api.Application.
func (app *keymanagerApplication) Name() string {
	return AppName
}

// ID implements api.Application.
func (app *keymanagerApplication) ID() uint8 {
	return AppID
}

// Methods implements api.Application.
func (app *keymanagerApplication) Methods() []transaction.MethodName {
	return app.methods
}

// Blessed implements api.Application.
func (app *keymanagerApplication) Blessed() bool {
	return false
}

// Dependencies implements api.Application.
func (app *keymanagerApplication) Dependencies() []string {
	return []string{registryapp.AppName}
}

// OnRegister implements api.Application.
func (app *keymanagerApplication) OnRegister(state tmapi.ApplicationState, md tmapi.MessageDispatcher) {
	app.state = state

	for _, ext := range app.exts {
		ext.OnRegister(state, md)
	}
}

// OnCleanup implements api.Application.
func (app *keymanagerApplication) OnCleanup() {}

// BeginBlock implements api.Application.
func (app *keymanagerApplication) BeginBlock(ctx *tmapi.Context) error {
	// Prioritize application-specific logic.
	if changed, _ := app.state.EpochChanged(ctx); changed {
		if err := suspendRuntimes(ctx); err != nil {
			return err
		}
	}

	// Proceed with extension-specific logic.
	for _, ext := range app.exts {
		if err := ext.BeginBlock(ctx); err != nil {
			return err
		}
	}

	return nil
}

// ExecuteMessage implements api.Application.
func (app *keymanagerApplication) ExecuteMessage(*tmapi.Context, interface{}, interface{}) (interface{}, error) {
	return nil, fmt.Errorf("keymanager: unexpected message")
}

// ExecuteTx implements api.Application.
func (app *keymanagerApplication) ExecuteTx(ctx *tmapi.Context, tx *transaction.Transaction) error {
	ctx.SetPriority(AppPriority)

	ext, ok := app.extsByMethod[tx.Method]
	if !ok {
		return fmt.Errorf("keymanager: invalid method: %s", tx.Method)
	}

	return ext.ExecuteTx(ctx, tx)
}

// EndBlock implements api.Application.
func (app *keymanagerApplication) EndBlock(*tmapi.Context) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

// suspendRuntimes suspends runtimes if registering entities no longer possess enough stake
// to cover the entity and runtime deposits.
func suspendRuntimes(ctx *tmapi.Context) error {
	regState := registryState.NewMutableState(ctx.State())
	stakeState := stakingState.NewMutableState(ctx.State())

	params, err := stakeState.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to get consensus parameters: %w", err)
	}
	if params.DebugBypassStake {
		return nil
	}

	stakeAcc, err := stakingState.NewStakeAccumulatorCache(ctx)
	if err != nil {
		return fmt.Errorf("failed to create stake accumulator cache: %w", err)
	}
	defer stakeAcc.Discard()

	runtimes, _ := regState.Runtimes(ctx)
	for _, rt := range runtimes {
		if rt.Kind != registry.KindKeyManager {
			continue
		}

		if rt.GovernanceModel == registry.GovernanceConsensus {
			continue
		}

		acctAddr := rt.StakingAddress()
		if acctAddr == nil {
			// This should never happen.
			ctx.Logger().Error("unknown runtime governance model",
				"rt_id", rt.ID,
				"gov_model", rt.GovernanceModel,
			)
			return fmt.Errorf("unknown runtime governance model on runtime %s: %s", rt.ID, rt.GovernanceModel)
		}

		if err = stakeAcc.CheckStakeClaims(*acctAddr); err == nil {
			continue
		}

		ctx.Logger().Debug("insufficient stake for key manager runtime operation",
			"err", err,
			"entity", rt.EntityID,
			"account", *acctAddr,
		)

		if err := regState.SuspendRuntime(ctx, rt.ID); err != nil {
			return err
		}
	}

	return nil
}

func (app *keymanagerApplication) registerExtensions(exts ...tmapi.Extension) {
	for _, ext := range exts {
		for _, m := range ext.Methods() {
			if _, ok := app.extsByMethod[m]; ok {
				panic(fmt.Sprintf("keymanager: method already registered: %s", m))
			}
			app.extsByMethod[m] = ext
			app.methods = append(app.methods, m)
		}
		app.exts = append(app.exts, ext)
	}
}

// New constructs a new keymanager application instance.
func New() tmapi.Application {
	app := keymanagerApplication{
		exts:         make([]tmapi.Extension, 0),
		methods:      make([]transaction.MethodName, 0),
		extsByMethod: make(map[transaction.MethodName]tmapi.Extension),
	}

	app.registerExtensions(secrets.New(app.Name()))
	app.registerExtensions(churp.New(app.Name()))

	return &app
}
