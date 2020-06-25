package e2e

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"

	"github.com/oasisprotocol/oasis-core/go/common"
	//"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// RuntimeUpgrade is the runtime upgrade scenario.
var RuntimeUpgrade scenario.Scenario = newRuntimeUpgradeImpl()

type runtimeUpgradeImpl struct {
	runtimeImpl

	nonce uint64
}

func newRuntimeUpgradeImpl() scenario.Scenario {
	return &runtimeUpgradeImpl{
		runtimeImpl: *newRuntimeImpl(
			"runtime-upgrade",
			"simple-keyvalue-enc-client",
			nil,
		),
	}
}

func (sc *runtimeUpgradeImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Get number of compute runtimes.
	var computeIndex int
	for i := range f.Runtimes {
		if f.Runtimes[i].Kind == registry.KindCompute {
			computeIndex = i
			break
		}
	}

	// Load the upgraded runtime binary.
	newRuntimeBinary, err := sc.resolveRuntimeBinary("simple-keyvalue-upgrade")
	if err != nil {
		return nil, fmt.Errorf("error resolving binary: %w", err)
	}

	// Setup the upgraded runtime (first is keymanager, others should be generic compute).
	runtimeFix := f.Runtimes[computeIndex]
	if runtimeFix.Kind != registry.KindCompute {
		return nil, fmt.Errorf("expected second runtime in fixture to be compute runtime, got: %s", runtimeFix.Kind)
	}
	runtimeFix.Binaries = append([]string{newRuntimeBinary}, runtimeFix.Binaries...)

	// The upgraded runtime will be registered later.
	runtimeFix.ExcludeFromGenesis = true
	newComputeIndex := len(f.Runtimes)
	f.Runtimes = append(f.Runtimes, runtimeFix)

	// Add the upgraded compute rutimes, will be started later.
	workers := len(f.ComputeWorkers)
	for _, worker := range f.ComputeWorkers {
		worker.RuntimeOverride = []int{computeIndex}
	}
	for i := 0; i < workers; i++ {
		f.ComputeWorkers = append(f.ComputeWorkers, oasis.ComputeWorkerFixture{Entity: 1, NoAutoStart: true, RuntimeOverride: []int{newComputeIndex}})
	}

	f.Network.IAS.UseRegistry = true

	return f, nil
}

func (sc *runtimeUpgradeImpl) Clone() scenario.Scenario {
	return &runtimeUpgradeImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *runtimeUpgradeImpl) applyUpgradePolicy(childEnv *env.Env) error {
	cli := cli.New(childEnv, sc.net, sc.logger)

	kmPolicyPath := filepath.Join(childEnv.Dir(), "km_policy.cbor")
	kmPolicySig1Path := filepath.Join(childEnv.Dir(), "km_policy_sig1.pem")
	kmPolicySig2Path := filepath.Join(childEnv.Dir(), "km_policy_sig2.pem")
	kmPolicySig3Path := filepath.Join(childEnv.Dir(), "km_policy_sig3.pem")
	kmUpdateTxPath := filepath.Join(childEnv.Dir(), "km_gen_update.json")

	oldRuntime := sc.net.Runtimes()[1]
	newRuntime := sc.net.Runtimes()[2]
	// Sanity check fixture.
	if err := func() error {
		if oldRuntime.Kind() != registry.KindCompute {
			return fmt.Errorf("old runtime not of kind KindCompute")
		}
		if newRuntime.Kind() != registry.KindCompute {
			return fmt.Errorf("new runtime not of kind KindCompute")
		}
		if oldRuntime.ID() != newRuntime.ID() {
			return fmt.Errorf("runtime ID mismatch")
		}
		return nil
	}(); err != nil {
		return fmt.Errorf("runtimes fixture sanity check: %w", err)
	}

	oldRuntimeEncID := oldRuntime.GetEnclaveIdentity()
	newRuntimeEncID := newRuntime.GetEnclaveIdentity()

	if oldRuntimeEncID == nil && newRuntimeEncID == nil {
		sc.logger.Info("No SGX runtimes, skipping policy update")
		return nil
	}

	// Ensure enclave IDs differ between the old and new runtimes.
	oldEncID, _ := oldRuntimeEncID.MarshalText()
	newEncID, _ := newRuntimeEncID.MarshalText()
	if bytes.Equal(oldEncID, newEncID) {
		return fmt.Errorf("expected different enclave identities, got: %s", newEncID)
	}

	// Build updated SGX policies.
	sc.logger.Info("building new KM SGX policy enclave policies map")
	enclavePolicies := make(map[sgx.EnclaveIdentity]*keymanager.EnclavePolicySGX)

	enclavePolicies[*newRuntimeEncID] = &keymanager.EnclavePolicySGX{}
	enclavePolicies[*newRuntimeEncID].MayQuery = make(map[common.Namespace][]sgx.EnclaveIdentity)
	enclavePolicies[*oldRuntimeEncID] = &keymanager.EnclavePolicySGX{}
	enclavePolicies[*oldRuntimeEncID].MayQuery = make(map[common.Namespace][]sgx.EnclaveIdentity)

	// Allow compute runtime to query new runtime.
	for _, rt := range sc.net.Runtimes() {
		if rt.Kind() != registry.KindCompute {
			continue
		}
		if eid := rt.GetEnclaveIdentity(); eid != nil {
			enclavePolicies[*newRuntimeEncID].MayQuery[rt.ID()] = []sgx.EnclaveIdentity{*eid}
		}
	}

	sc.logger.Info("initing updated KM policy")
	if err := cli.Keymanager.InitPolicy(oldRuntime.ID(), 2, enclavePolicies, kmPolicyPath); err != nil {
		return err
	}
	sc.logger.Info("signing updated KM policy")
	if err := cli.Keymanager.SignPolicy("1", kmPolicyPath, kmPolicySig1Path); err != nil {
		return err
	}
	if err := cli.Keymanager.SignPolicy("2", kmPolicyPath, kmPolicySig2Path); err != nil {
		return err
	}
	if err := cli.Keymanager.SignPolicy("3", kmPolicyPath, kmPolicySig3Path); err != nil {
		return err
	}

	sc.logger.Info("updating KM policy")
	if err := cli.Keymanager.GenUpdate(sc.nonce, kmPolicyPath, []string{kmPolicySig1Path, kmPolicySig2Path, kmPolicySig3Path}, kmUpdateTxPath); err != nil {
		return err
	}
	if err := cli.Consensus.SubmitTx(kmUpdateTxPath); err != nil {
		return fmt.Errorf("failed to update KM policy: %w", err)
	}
	sc.nonce++

	return nil
}

func (sc *runtimeUpgradeImpl) Run(childEnv *env.Env) error {
	ctx := context.Background()
	cli := cli.New(childEnv, sc.net, sc.logger)

	computeWorkers := len(sc.net.ComputeWorkers())

	clientErrCh, cmd, err := sc.runtimeImpl.start(childEnv)
	if err != nil {
		return err
	}
	sc.logger.Info("waiting for client to exit")
	// Wait for the client to exit.
	select {
	case err = <-sc.runtimeImpl.net.Errors():
		_ = cmd.Process.Kill()
	case err = <-clientErrCh:
	}
	if err != nil {
		return err
	}

	// Generate and update a policy that will allow the new runtime to run.
	if err = sc.applyUpgradePolicy(childEnv); err != nil {
		return fmt.Errorf("updating policies: %w", err)
	}

	// Kill old compute workers.
	sc.logger.Info("stopping old runtimes")
	for i := 0; i < computeWorkers/2; i++ {
		worker := sc.net.ComputeWorkers()[i]
		if err = worker.Stop(); err != nil {
			return fmt.Errorf("stopping old compute worker: %w", err)
		}
	}

	// Start the new compute workers.
	sc.logger.Info("starting new runtimes")
	for i := computeWorkers / 2; i < computeWorkers; i++ {
		newWorker := sc.net.ComputeWorkers()[i]
		if err = newWorker.Start(); err != nil {
			return fmt.Errorf("starting new compute worker: %w", err)
		}
	}

	// Update runtime to include the new enclave identity.
	sc.logger.Info("updating runtime descriptor")
	newRt := sc.net.Runtimes()[len(sc.net.Runtimes())-1]
	newRtDesc := newRt.ToRuntimeDescriptor()
	newTxPath := filepath.Join(childEnv.Dir(), "register_update_compute_runtime.json")
	if err = cli.Registry.GenerateRegisterRuntimeTx(sc.nonce, newRtDesc, newTxPath, ""); err != nil {
		return fmt.Errorf("failed to generate register compute runtime tx: %w", err)
	}
	sc.nonce++
	if err = cli.Consensus.SubmitTx(newTxPath); err != nil {
		return fmt.Errorf("failed to update compute runtime: %w", err)
	}

	// Wait for the new nodes to register.
	sc.logger.Info("waiting for new compute nodes to register",
		"num_nodes", sc.net.NumRegisterNodes(),
	)

	if err = sc.net.Controller().WaitNodesRegistered(ctx, sc.net.NumRegisterNodes()); err != nil {
		return fmt.Errorf("failed to wait for nodes: %w", err)
	}

	sc.logger.Info("wait for few epochs")
	var waitEpoch epochtime.EpochTime
	waitEpoch, err = sc.net.Controller().Consensus.GetEpoch(ctx, 0)
	if err != nil {
		return err
	}
	waitEpoch += 3
	sc.logger.Info("waiting for epoch",
		"wait_epoch", waitEpoch,
	)
	err = sc.net.Controller().Consensus.WaitEpoch(ctx, waitEpoch)
	if err != nil {
		return err
	}

	// Shutdown old workers.
	sc.logger.Info("shutting down old compute workers")
	for i := 0; i < computeWorkers/2; i++ {
		oldWorker := sc.net.ComputeWorkers()[i]
		if err = oldWorker.Stop(); err != nil {
			return fmt.Errorf("old compute worker node shutdown: %w", err)
		}
	}

	// Run client again.
	sc.logger.Info("starting a second client to check if runtime works")
	sc.runtimeImpl.clientArgs = []string{"--key", "key2"}
	cmd, err = sc.startClient(childEnv)
	if err != nil {
		return err
	}
	client2ErrCh := make(chan error)
	go func() {
		client2ErrCh <- cmd.Wait()
	}()
	return sc.wait(childEnv, cmd, client2ErrCh)
}
