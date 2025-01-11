package scheduler

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/cometbft/cometbft/abci/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/scheduler/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func (app *schedulerApplication) InitChain(ctx *abciAPI.Context, req types.RequestInitChain, doc *genesis.Document) error {
	var err error
	state := schedulerState.NewMutableState(ctx.State())
	if err = state.SetConsensusParameters(ctx, &doc.Scheduler.Parameters); err != nil {
		return fmt.Errorf("failed to set consensus parameters: %w", err)
	}

	if doc.Scheduler.Parameters.MinValidators <= 0 {
		return fmt.Errorf("cometbft/scheduler: minimum number of validators not configured")
	}
	if doc.Scheduler.Parameters.MaxValidators <= 0 {
		return fmt.Errorf("cometbft/scheduler: maximum number of validators not configured")
	}
	if doc.Scheduler.Parameters.MaxValidatorsPerEntity <= 0 {
		return fmt.Errorf("cometbft/scheduler: maximum number of validators per entity not configured")
	}
	if doc.Scheduler.Parameters.MaxValidatorsPerEntity > 1 {
		// This should only ever be true for test deployments.
		ctx.Logger().Warn("maximum number of validators is non-standard, fairness not guaranteed",
			"max_valiators_per_entity", doc.Scheduler.Parameters.MaxValidatorsPerEntity,
		)
	}

	regState := registryState.NewMutableState(ctx.State())
	nodes, err := regState.Nodes(ctx)
	if err != nil {
		return fmt.Errorf("cometbft/scheduler: couldn't get nodes: %w", err)
	}

	registeredValidators := make(map[signature.PublicKey]*node.Node)
	for _, v := range nodes {
		if v.HasRoles(node.RoleValidator) {
			registeredValidators[v.Consensus.ID] = v
		}
	}

	stakeState := stakingState.NewMutableState(ctx.State())

	// Assemble the list of the CometBFT genesis validators, and do some
	// sanity checking.
	currentValidators := make(map[signature.PublicKey]*scheduler.Validator)
	for _, v := range req.Validators {
		tmPk := v.GetPubKey()
		pk := tmPk.GetEd25519()

		if pk == nil {
			ctx.Logger().Error("invalid genesis validator public key type",
				"type", v.GetPubKey(),
			)
			return fmt.Errorf("scheduler: invalid genesis validator public key type: '%v'", v.GetPubKey())
		}

		var id signature.PublicKey
		if err = id.UnmarshalBinary(pk); err != nil {
			ctx.Logger().Error("invalid genesis validator public key",
				"err", err,
				"public_key", hex.EncodeToString(pk),
			)
			return fmt.Errorf("scheduler: invalid genesis validator public key: %w", err)
		}

		n := registeredValidators[id]
		if n == nil {
			ctx.Logger().Error("genesis validator not in registry",
				"id", id,
			)
			return fmt.Errorf("scheduler: genesis validator not in registry")
		}

		var expectedPower int64
		if doc.Scheduler.Parameters.DebugBypassStake {
			expectedPower = 1
		} else {
			var account *staking.Account
			acctAddr := staking.NewAddress(n.EntityID)
			account, err = stakeState.Account(ctx, acctAddr)
			if err != nil {
				ctx.Logger().Error("couldn't get account for genesis validator entity",
					"err", err,
					"node", n.ID,
					"entity", n.EntityID,
					"accont", acctAddr,
				)
				return fmt.Errorf("scheduler: getting account %s for genesis validator %s of entity %s: %w",
					acctAddr,
					n.ID,
					n.EntityID,
					err,
				)
			}
			expectedPower, err = scheduler.VotingPowerFromStake(&account.Escrow.Active.Balance, doc.Scheduler.Parameters.VotingPowerDistribution)
			if err != nil {
				ctx.Logger().Error("computing voting power from stake failed",
					"err", err,
					"node", n.ID,
					"entity", n.EntityID,
					"account", acctAddr,
					"stake", &account.Escrow.Active.Balance,
				)
				return fmt.Errorf(
					"scheduler: computing voting power from stake (node %s entity %s account %s stake %v): %w",
					n.ID,
					n.EntityID,
					acctAddr,
					&account.Escrow.Active.Balance,
					err,
				)
			}
		}
		if v.Power != expectedPower {
			ctx.Logger().Error("validator power is wrong",
				"node_id", n.ID,
				"expected_power", expectedPower,
				"validator_power", v.Power,
			)
			return fmt.Errorf("scheduler: genesis validator node %s has wrong power %d, expected %d",
				n.ID,
				v.Power,
				expectedPower,
			)
		}

		ctx.Logger().Debug("adding validator to current validator set",
			"id", id,
		)
		currentValidators[n.Consensus.ID] = &scheduler.Validator{
			ID:          n.ID,
			EntityID:    n.EntityID,
			VotingPower: v.Power,
		}
	}

	// TODO/security: Enforce genesis validator staking thresholds.

	// Add the current validator set to ABCI, so that we can alter it later.
	//
	// Sort of stupid it needs to be done this way, but CometBFT doesn't
	// appear to pass ABCI the validator set anywhere other than InitChain.
	if err = state.PutCurrentValidators(ctx, currentValidators); err != nil {
		return fmt.Errorf("failed to set validator set: %w", err)
	}

	if !doc.Scheduler.Parameters.DebugBypassStake {
		supplyPower, err := scheduler.VotingPowerFromStake(&doc.Staking.TotalSupply, doc.Scheduler.Parameters.VotingPowerDistribution)
		if err != nil {
			return fmt.Errorf("init chain: total supply would break voting power computation: %w", err)
		}
		if supplyPower > cmttypes.MaxTotalVotingPower {
			return fmt.Errorf("init chain: total supply power %d exceeds CometBFT voting power limit %d", supplyPower, cmttypes.MaxTotalVotingPower)
		}
	}

	return nil
}

func (sq *schedulerQuerier) Genesis(ctx context.Context) (*scheduler.Genesis, error) {
	params, err := sq.state.ConsensusParameters(ctx)
	if err != nil {
		return nil, err
	}

	genesis := &scheduler.Genesis{
		Parameters: *params,
	}
	return genesis, nil
}
