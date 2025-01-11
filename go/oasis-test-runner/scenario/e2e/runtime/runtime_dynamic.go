package runtime

import (
	"context"
	"fmt"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// RuntimeDynamic is the dynamic runtime registration scenario.
var RuntimeDynamic scenario.Scenario = newRuntimeDynamicImpl()

type runtimeDynamicImpl struct {
	Scenario

	epoch beacon.EpochTime
}

func newRuntimeDynamicImpl() scenario.Scenario {
	return &runtimeDynamicImpl{
		Scenario: *NewScenario("runtime-dynamic", nil),
	}
}

func (sc *runtimeDynamicImpl) Clone() scenario.Scenario {
	return &runtimeDynamicImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
		epoch:    sc.epoch,
	}
}

func (sc *runtimeDynamicImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Allocate stake and set runtime thresholds.
	f.Network.StakingGenesis = &staking.Genesis{
		Parameters: staking.ConsensusParameters{
			Thresholds: map[staking.ThresholdKind]quantity.Quantity{
				staking.KindEntity:            *quantity.NewFromUint64(0),
				staking.KindNodeValidator:     *quantity.NewFromUint64(0),
				staking.KindNodeCompute:       *quantity.NewFromUint64(0),
				staking.KindNodeObserver:      *quantity.NewFromUint64(0),
				staking.KindNodeKeyManager:    *quantity.NewFromUint64(0),
				staking.KindRuntimeCompute:    *quantity.NewFromUint64(1000),
				staking.KindRuntimeKeyManager: *quantity.NewFromUint64(1000),
				staking.KindKeyManagerChurp:   *quantity.NewFromUint64(0),
			},
		},
	}
	// Avoid unexpected blocks.
	f.Network.SetMockEpoch()
	// Exclude all runtimes from genesis as we will register those dynamically.
	for i := range f.Runtimes {
		f.Runtimes[i].ExcludeFromGenesis = true
	}
	// Test with a non-zero round.
	f.Runtimes[1].GenesisRound = 42

	return f, nil
}

func (sc *runtimeDynamicImpl) epochTransition(ctx context.Context) error {
	sc.epoch++

	sc.Logger.Info("triggering epoch transition",
		"epoch", sc.epoch,
	)
	if err := sc.Net.Controller().SetEpoch(ctx, sc.epoch); err != nil {
		return fmt.Errorf("failed to set epoch: %w", err)
	}
	sc.Logger.Info("epoch transition done")
	return nil
}

func (sc *runtimeDynamicImpl) Run(ctx context.Context, childEnv *env.Env) error { // nolint: gocyclo
	var rtNonce uint64
	if err := sc.Net.Start(); err != nil {
		return err
	}

	cli := cli.New(childEnv, sc.Net, sc.Logger)

	// Wait for all nodes to be synced before we proceed.
	if err := sc.WaitNodesSynced(ctx); err != nil {
		return err
	}

	// Wait for validator nodes to register.
	sc.Logger.Info("waiting for validator nodes to initialize",
		"num_validators", len(sc.Net.Validators()),
	)
	for _, n := range sc.Net.Validators() {
		if err := n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a validator: %w", err)
		}
	}

	// Perform an initial epoch transition to make sure that the nodes can handle it even though
	// there are no runtimes registered yet.
	if err := sc.epochTransition(ctx); err != nil {
		return err
	}

	// Nonce used for transactions (increase this by 1 after each transaction).
	var nonce uint64

	// Fetch current epoch.
	epoch, err := sc.Net.Controller().Beacon.GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to get current epoch: %w", err)
	}

	// Register a new keymanager runtime.
	kmRt := sc.Net.Runtimes()[0]
	rtDsc := kmRt.ToRuntimeDescriptor()
	rtDsc.Deployments[0].ValidFrom = epoch + 1
	if err = sc.RegisterRuntime(childEnv, cli, rtDsc, nonce); err != nil {
		return err
	}
	nonce++

	// Generate and update the new keymanager runtime's policy.
	policies, err := sc.BuildEnclavePolicies()
	if err != nil {
		return err
	}
	switch policies {
	case nil:
		sc.Logger.Info("no SGX runtimes, skipping policy update")

		// In non-SGX mode, the policy update fails with a policy checksum
		// mismatch (the non-SGX KM returns an empty policy), so we need to
		// do an epoch transition instead (to complete the KM runtime
		// registration).
		if err = sc.epochTransition(ctx); err != nil {
			return err
		}
	default:
		// In SGX mode, we can update the policy as intended.
		if err = sc.ApplyKeyManagerPolicy(ctx, childEnv, cli, 0, policies, nonce); err != nil {
			return err
		}
		nonce++
	}

	// Wait for key manager nodes to register, then make another epoch transition.
	sc.Logger.Info("waiting for key manager nodes to initialize",
		"num_keymanagers", len(sc.Net.Keymanagers()),
	)
	for _, n := range sc.Net.Keymanagers() {
		if err = n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a validator: %w", err)
		}
	}
	if err = sc.epochTransition(ctx); err != nil {
		return err
	}

	// Fetch current epoch.
	epoch, err = sc.Net.Controller().Beacon.GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to get current epoch: %w", err)
	}

	// Register a new compute runtime.
	compRt := sc.Net.Runtimes()[1]
	compRtDesc := compRt.ToRuntimeDescriptor()
	compRtDesc.Deployments[0].ValidFrom = epoch + 1
	if err = sc.RegisterRuntime(childEnv, cli, compRtDesc, nonce); err != nil {
		return err
	}
	nonce++

	// Wait for compute workers to become ready.
	sc.Logger.Info("waiting for compute workers to initialize",
		"num_compute_workers", len(sc.Net.ComputeWorkers()),
	)
	for _, n := range sc.Net.ComputeWorkers() {
		if err = n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a compute worker: %w", err)
		}
	}

	// Perform an epoch transition to make sure all nodes are eligible. They may not be eligible
	// if they have registered after the beacon commit phase.
	if err = sc.epochTransition(ctx); err != nil {
		return err
	}

	for i := 0; i < 5; i++ {
		// Perform another epoch transition to elect compute runtime committees.
		if err = sc.epochTransition(ctx); err != nil {
			return err
		}

		// Wait a bit after epoch transitions.
		time.Sleep(1 * time.Second)

		// Submit a runtime transaction.
		sc.Logger.Info("submitting transaction to runtime",
			"seq", i,
		)
		if _, err = sc.submitKeyValueRuntimeInsertTx(ctx, KeyValueRuntimeID, rtNonce, "hello", fmt.Sprintf("world %d", i), 0, 0, plaintextTxKind); err != nil {
			return err
		}
		rtNonce++
	}

	// Stop all runtime nodes, so they will not re-register, causing the nodes to expire.
	sc.Logger.Info("stopping compute nodes")
	for _, n := range sc.Net.ComputeWorkers() {
		if err = n.Stop(); err != nil {
			return fmt.Errorf("failed to stop node: %w", err)
		}
	}

	registyCh, sub, err := sc.Net.Controller().Registry.WatchEvents(ctx)
	if err != nil {
		return fmt.Errorf("failed to watch events: %w", err)
	}
	defer sub.Close()
	ensureRuntimeEvents := func(suspended bool) error {
		// Ensure expected suspended/started event is received.
		for {
			select {
			case evt := <-registyCh:
				sc.Logger.Debug("received event", "event", evt)
				switch suspended {
				case true:
					if evt.RuntimeSuspendedEvent == nil {
						continue
					}
					if !compRtDesc.ID.Equal(&evt.RuntimeSuspendedEvent.RuntimeID) {
						continue
					}
					return nil
				default:
					if evt.RuntimeStartedEvent == nil {
						continue
					}
					if !compRtDesc.ID.Equal(&evt.RuntimeStartedEvent.Runtime.ID) {
						continue
					}
					return nil
				}
			case <-time.After(10 * time.Second):
				return fmt.Errorf("failed to receive runtime event for: %s (suspended: %t)", compRtDesc.ID, suspended)
			}
		}
	}

	// Epoch transitions so nodes expire.
	sc.Logger.Info("performing epoch transitions so nodes expire")
	for i := 0; i < 3; i++ {
		if err = sc.epochTransition(ctx); err != nil {
			return err
		}

		// Wait a bit between epoch transitions.
		time.Sleep(1 * time.Second)
	}

	// Ensure that runtime got suspended.
	sc.Logger.Info("checking that runtime got suspended")
	_, err = sc.Net.Controller().Registry.GetRuntime(ctx, &registry.GetRuntimeQuery{
		Height: consensus.HeightLatest,
		ID:     compRtDesc.ID,
	})
	switch err {
	case nil:
		return fmt.Errorf("runtime should be suspended but it is not")
	case registry.ErrNoSuchRuntime:
		// Runtime is suspended.
	default:
		return fmt.Errorf("unexpected error while fetching runtime: %w", err)
	}
	if err = ensureRuntimeEvents(true); err != nil {
		return err
	}

	// Start runtime nodes, make sure they register.
	sc.Logger.Info("starting compute nodes")
	for _, n := range sc.Net.ComputeWorkers() {
		if err = n.Start(); err != nil {
			return fmt.Errorf("failed to start node: %w", err)
		}
	}

	sc.Logger.Info("waiting for compute workers to initialize",
		"num_compute_workers", len(sc.Net.ComputeWorkers()),
	)
	for _, n := range sc.Net.ComputeWorkers() {
		if err = n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a compute worker: %w", err)
		}
	}

	// Perform an epoch transition to make sure all nodes are eligible. They may not be eligible
	// if they have registered after the beacon commit phase.
	if err = sc.epochTransition(ctx); err != nil {
		return err
	}

	// Epoch transition.
	if err = sc.epochTransition(ctx); err != nil {
		return err
	}

	// Submit a runtime transaction to check whether the runtimes got resumed.
	sc.Logger.Info("submitting transaction to runtime")
	if _, err = sc.submitKeyValueRuntimeInsertTx(ctx, KeyValueRuntimeID, rtNonce, "hello", "final world", 0, 0, plaintextTxKind); err != nil {
		return err
	}
	rtNonce++

	// Now reclaim all stake from the debug entity which owns the runtime.
	sc.Logger.Info("reclaiming stake from entity which owns the runtime")
	entSigner := sc.Net.Entities()[0].Signer()
	entAddr := staking.NewAddress(entSigner.Public())
	var oneShare quantity.Quantity
	_ = oneShare.FromUint64(1)
	tx := staking.NewReclaimEscrowTx(nonce, &transaction.Fee{Gas: 10000}, &staking.ReclaimEscrow{
		Account: entAddr,
		Shares:  oneShare,
	})
	nonce++
	sigTx, err := transaction.Sign(entSigner, tx)
	if err != nil {
		return fmt.Errorf("failed to sign reclaim: %w", err)
	}
	if err = sc.Net.Controller().Consensus.SubmitTx(ctx, sigTx); err != nil {
		return fmt.Errorf("failed to reclaim stake: %w", err)
	}

	// Watch node registrations so we know when node re-register. We want to ensure that node
	// re-registrations will not cause the runtimes to be resumed.
	nodeCh, nodeSub, err := sc.Net.Controller().Registry.WatchNodes(ctx)
	if err != nil {
		return fmt.Errorf("failed to watch nodes: %w", err)
	}
	defer nodeSub.Close()

	// Epoch transition to make the debonding period expire.
	if err = sc.epochTransition(ctx); err != nil {
		return err
	}

	// Wait a bit to give the nodes time to renew their registration.
	waitForNodeUpdates := func() error {
		sc.Logger.Info("waiting for node re-registrations")
		nodeUpdates := make(map[signature.PublicKey]bool)
		for {
			select {
			case ev := <-nodeCh:
				if ev.IsRegistration {
					nodeUpdates[ev.Node.ID] = true
					if len(nodeUpdates) == sc.Net.NumRegisterNodes() {
						return nil
					}
				}
			case <-time.After(10 * time.Second):
				return fmt.Errorf("failed to wait for all nodes to re-register")
			}
		}
	}
	if err = waitForNodeUpdates(); err != nil {
		return err
	}

	// Ensure that runtimes got suspended.
	ensureRuntimesSuspended := func(suspended bool) error {
		sc.Logger.Info("checking that runtimes got (un)suspended")
		for _, rt := range sc.Net.Runtimes() {
			_, err = sc.Net.Controller().Registry.GetRuntime(ctx, &registry.GetRuntimeQuery{
				Height: consensus.HeightLatest,
				ID:     rt.ID(),
			})
			switch err {
			case nil:
				if suspended {
					return fmt.Errorf("runtime %s should be suspended but it is not", rt.ID())
				}
			case registry.ErrNoSuchRuntime:
				// Runtime is suspended.
				if !suspended {
					return fmt.Errorf("runtime %s should NOT be suspended but it is", rt.ID())
				}
			default:
				return fmt.Errorf("unexpected error while fetching runtime %s: %w", rt.ID(), err)
			}
		}
		return nil
	}
	if err = ensureRuntimesSuspended(true); err != nil {
		return err
	}
	if err = ensureRuntimeEvents(true); err != nil {
		return err
	}

	// Restart nodes to test that the nodes will re-register although
	// the runtime is suspended.
	sc.Logger.Info("Restarting compute node to ensure it re-registers")
	if err = sc.Net.ComputeWorkers()[0].Stop(); err != nil {
		return fmt.Errorf("failed to stop node: %w", err)
	}
	if err = sc.Net.ComputeWorkers()[0].Start(); err != nil {
		return fmt.Errorf("failed to start node: %w", err)
	}

	// Another epoch transition to make sure the runtime keeps being suspended.
	if err = sc.epochTransition(ctx); err != nil {
		return err
	}

	// Wait for node updates again.
	if err = waitForNodeUpdates(); err != nil {
		return err
	}

	// Ensure that runtimes are still suspended.
	if err = ensureRuntimesSuspended(true); err != nil {
		return err
	}

	// Now escrow the stake back.
	sc.Logger.Info("escrowing stake back")
	var enoughStake quantity.Quantity
	_ = enoughStake.FromUint64(100_000)
	tx = staking.NewAddEscrowTx(nonce, &transaction.Fee{Gas: 10000}, &staking.Escrow{
		Account: entAddr,
		Amount:  enoughStake,
	})
	nonce++
	sigTx, err = transaction.Sign(entSigner, tx)
	if err != nil {
		return fmt.Errorf("failed to sign escrow: %w", err)
	}
	if err = sc.Net.Controller().Consensus.SubmitTx(ctx, sigTx); err != nil {
		return fmt.Errorf("failed to escrow stake: %w", err)
	}

	// Another epoch transition to trigger node re-registration.
	if err = sc.epochTransition(ctx); err != nil {
		return err
	}

	// Wait for node updates yet again.
	if err = waitForNodeUpdates(); err != nil {
		return err
	}

	// Now runtimes should no longer be suspended.
	if err = ensureRuntimesSuspended(false); err != nil {
		return err
	}
	if err = ensureRuntimeEvents(false); err != nil {
		return err
	}

	// Another epoch transition to elect committees.
	if err = sc.epochTransition(ctx); err != nil {
		return err
	}

	// Transition the runtime governance model to runtime.
	compRtDesc.GovernanceModel = registry.GovernanceRuntime
	// Ensure runtime account has enough stake.
	tx = staking.NewAddEscrowTx(nonce, &transaction.Fee{Gas: 10000}, &staking.Escrow{
		Account: *compRtDesc.StakingAddress(),
		Amount:  enoughStake,
	})
	nonce++
	sigTx, err = transaction.Sign(entSigner, tx)
	if err != nil {
		return fmt.Errorf("failed to sign escrow: %w", err)
	}
	if err = sc.Net.Controller().Consensus.SubmitTx(ctx, sigTx); err != nil {
		return fmt.Errorf("failed to escrow stake: %w", err)
	}
	// Update the runtime governance model.
	if err = sc.RegisterRuntime(childEnv, cli, compRtDesc, nonce); err != nil {
		return err
	}
	nonce++ // nolint: ineffassign

	// Submit a runtime transaction to check whether the runtimes got resumed.
	sc.Logger.Info("submitting transaction to runtime")
	if _, err = sc.submitKeyValueRuntimeInsertTx(ctx, KeyValueRuntimeID, rtNonce, "hello", "final world for sure", 0, 0, plaintextTxKind); err != nil {
		return err
	}

	return nil
}
