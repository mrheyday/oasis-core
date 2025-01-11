package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/rust"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	commonWorker "github.com/oasisprotocol/oasis-core/go/worker/common/api"
)

var (
	// KeyValueRuntimeBinary is the name of the simple key/value runtime binary.
	KeyValueRuntimeBinary = "simple-keyvalue"
	// KeyValueRuntimeUpgradeBinary is the name of the upgraded simple key/value runtime binary.
	KeyValueRuntimeUpgradeBinary = "simple-keyvalue-upgrade"
	// KeyManagerRuntimeBinary is the name of the simple key manager runtime binary.
	KeyManagerRuntimeBinary = "simple-keymanager"
	// KeyManagerRuntimeUpgradeBinary is the name of the upgraded simple key manager runtime binary.
	KeyManagerRuntimeUpgradeBinary = "simple-keymanager-upgrade"
	// ROFLComponentBinary is the name of the ROFL runtime component binary.
	ROFLComponentBinary = "simple-rofl"

	// KeyValueRuntimeID is the ID of the simple key/value runtime.
	KeyValueRuntimeID common.Namespace
	// KeyManagerRuntimeID is the ID of the key manager runtime.
	KeyManagerRuntimeID common.Namespace

	_ = KeyManagerRuntimeID.UnmarshalHex("c000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff")
	_ = KeyValueRuntimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000")
)

// ResolveRuntimeBinaries returns the paths to the runtime binaries.
func (sc *Scenario) ResolveRuntimeBinaries(baseRuntimeBinary string) map[node.TEEHardware]string {
	binaries := make(map[node.TEEHardware]string)
	for _, tee := range []node.TEEHardware{
		node.TEEHardwareInvalid,
		node.TEEHardwareIntelSGX,
	} {
		binaries[tee] = sc.ResolveRuntimeBinary(baseRuntimeBinary, tee)
	}
	return binaries
}

// ResolveRuntimeBinary returns the path to the runtime binary.
func (sc *Scenario) ResolveRuntimeBinary(runtimeBinary string, tee node.TEEHardware) string {
	var runtimeExt, path string
	switch tee {
	case node.TEEHardwareInvalid:
		runtimeExt = ""
		path, _ = sc.Flags.GetString(cfgRuntimeBinaryDirDefault)
	case node.TEEHardwareIntelSGX:
		runtimeExt = ".sgxs"
		path, _ = sc.Flags.GetString(cfgRuntimeBinaryDirIntelSGX)
	}

	return filepath.Join(path, runtimeBinary+runtimeExt)
}

// BuildRuntimes builds the specified runtime binaries using the provided trust root, if given.
func (sc *Scenario) BuildRuntimes(childEnv *env.Env, runtimes map[common.Namespace]string, trustRoot *e2e.TrustRoot) error {
	// Determine the required directories for building the runtime with an embedded trust root.
	buildDir, targetDir, err := sc.BuildTargetDirs()
	if err != nil {
		return err
	}

	// Determine TEE hardware.
	teeHardware, err := sc.TEEHardware()
	if err != nil {
		return err
	}

	// Prepare the builder.
	builder := rust.NewBuilder(childEnv, buildDir, targetDir, teeHardware)

	// Build runtimes one by one.
	for runtimeID, runtimeBinary := range runtimes {
		switch trustRoot {
		case nil:
			sc.Logger.Info("building runtime without embedded trust root",
				"runtime_id", runtimeID,
				"runtime_binary", runtimeBinary,
			)
		default:
			sc.Logger.Info("building runtime with embedded trust root",
				"runtime_id", runtimeID,
				"runtime_binary", runtimeBinary,
				"trust_root_height", trustRoot.Height,
				"trust_root_hash", trustRoot.Hash,
				"trust_root_chain_context", trustRoot.ChainContext,
			)

			// Prepare environment.
			builder.SetEnv("OASIS_TESTS_CONSENSUS_TRUST_HEIGHT", trustRoot.Height)
			builder.SetEnv("OASIS_TESTS_CONSENSUS_TRUST_HASH", trustRoot.Hash)
			builder.SetEnv("OASIS_TESTS_CONSENSUS_TRUST_CHAIN_CONTEXT", trustRoot.ChainContext)
			builder.SetEnv("OASIS_TESTS_CONSENSUS_TRUST_RUNTIME_ID", runtimeID.String())
		}

		// Build a new runtime with the given trust root embedded.
		err = errors.Join(err, builder.Build(runtimeBinary))
	}
	if err != nil {
		return fmt.Errorf("failed to build runtimes: %w", err)
	}

	return nil
}

// BuildAllRuntimes builds all runtime binaries, i.e. the key/value and the key manager runtime.
func (sc *Scenario) BuildAllRuntimes(childEnv *env.Env, trustRoot *e2e.TrustRoot) error {
	runtimes := map[common.Namespace]string{
		KeyValueRuntimeID:   KeyValueRuntimeBinary,
		KeyManagerRuntimeID: KeyManagerRuntimeBinary,
	}

	return sc.BuildRuntimes(childEnv, runtimes, trustRoot)
}

// EnsureActiveVersionForComputeWorker ensures that the specified compute worker
// has the correct active version of the given runtime.
func (sc *Scenario) EnsureActiveVersionForComputeWorker(ctx context.Context, node *oasis.Compute, runtimeID common.Namespace, v version.Version) error {
	ctx, cancel := context.WithTimeout(ctx, versionActivationTimeout)
	defer cancel()

	sc.Logger.Info("ensuring that the compute worker has the correct active version",
		"node", node.Name,
		"runtime_id", runtimeID,
		"version", v,
	)

	nodeCtrl, err := oasis.NewController(node.SocketPath())
	if err != nil {
		return fmt.Errorf("%s: failed to create controller: %w", node.Name, err)
	}

	// Wait for the version to become active and ensure no suspension observed.
	for {
		status, err := nodeCtrl.GetStatus(ctx)
		if err != nil {
			return fmt.Errorf("%s: failed to query status: %w", node.Name, err)
		}

		provisioner := status.Runtimes[runtimeID].Provisioner
		if provisioner == "none" {
			return fmt.Errorf("%s: unexpected runtime provisioner for runtime '%s': %s", node.Name, runtimeID, provisioner)
		}

		cs := status.Runtimes[runtimeID].Committee
		if cs == nil {
			return fmt.Errorf("%s: missing status for runtime '%s'", node.Name, runtimeID)
		}

		if cs.ActiveVersion == nil {
			return fmt.Errorf("%s: no version is active", node.Name)
		}
		// Retry if not yet activated.
		if cs.ActiveVersion.ToU64() < v.ToU64() {
			sc.Logger.Warn("active version mismatch, waiting",
				"node", node.Name,
				"version", v,
				"active_version", cs.ActiveVersion,
			)

			time.Sleep(1 * time.Second)
			continue
		}
		if *cs.ActiveVersion != v {
			return fmt.Errorf("%s: unexpected active version (expected: %s got: %s)", node.Name, v, cs.ActiveVersion)
		}
		if cs.Status != commonWorker.StatusStateReady {
			sc.Logger.Warn("common worker not ready, waiting",
				"node", node.Name,
				"status", cs.Status,
			)

			time.Sleep(1 * time.Second)
			continue
		}
		break
	}

	return nil
}

// EnsureActiveVersionForComputeWorkers ensures that all compute workers
// have the correct active version of the given runtime.
func (sc *Scenario) EnsureActiveVersionForComputeWorkers(ctx context.Context, runtimeID common.Namespace, v version.Version) error {
	sc.Logger.Info("ensuring that all compute workers have the correct active version",
		"runtime_id", runtimeID,
		"version", v,
	)

	for _, node := range sc.Net.ComputeWorkers() {
		if err := sc.EnsureActiveVersionForComputeWorker(ctx, node, runtimeID, v); err != nil {
			return err
		}
	}
	return nil
}

// EnsureActiveVersionForKeyManager ensures that the specified key manager
// has the correct active version of the given runtime.
func (sc *Scenario) EnsureActiveVersionForKeyManager(ctx context.Context, node *oasis.Keymanager, runtimeID common.Namespace, v version.Version) error {
	ctx, cancel := context.WithTimeout(ctx, versionActivationTimeout)
	defer cancel()

	sc.Logger.Info("ensuring that the key manager has the correct active version",
		"node", node.Name,
		"runtime_id", runtimeID,
		"version", v,
	)

	nodeCtrl, err := oasis.NewController(node.SocketPath())
	if err != nil {
		return fmt.Errorf("%s: failed to create controller: %w", node.Name, err)
	}

	// Wait for the version to become active.
	for {
		status, err := nodeCtrl.GetStatus(ctx)
		if err != nil {
			return fmt.Errorf("%s: failed to query status: %w", node.Name, err)
		}

		if status.Keymanager == nil {
			return fmt.Errorf("%s: missing key manager status", node.Name)
		}

		ws := status.Keymanager
		if !runtimeID.Equal(ws.RuntimeID) {
			return fmt.Errorf("%s: unsupported runtime (expected: %s got: %s)", node.Name, ws.RuntimeID, runtimeID)
		}

		if ws.ActiveVersion == nil {
			return fmt.Errorf("%s: no version is active", node.Name)
		}
		// Retry if not yet activated.
		if ws.ActiveVersion.ToU64() < v.ToU64() {
			time.Sleep(1 * time.Second)
			continue
		}
		if *ws.ActiveVersion != v {
			return fmt.Errorf("%s: unexpected active version (expected: %s got: %s)", node.Name, v, ws.ActiveVersion)
		}
		break
	}

	return nil
}

// EnsureActiveVersionForKeyManagers ensures that all key managers
// have the correct active version of the given runtime.
func (sc *Scenario) EnsureActiveVersionForKeyManagers(ctx context.Context, runtimeID common.Namespace, v version.Version) error {
	sc.Logger.Info("ensuring that all key managers have the correct active version",
		"runtime_id", runtimeID,
		"version", v,
	)

	for _, node := range sc.Net.Keymanagers() {
		if err := sc.EnsureActiveVersionForKeyManager(ctx, node, runtimeID, v); err != nil {
			return err
		}
	}

	return nil
}

// EnableRuntimeDeployment registers the specified runtime deployment, updates the key manager
// policy, and waits until the deployment becomes active.
func (sc *Scenario) EnableRuntimeDeployment(ctx context.Context, childEnv *env.Env, cli *cli.Helpers, rt *oasis.Runtime, deploymentIndex int, nonce uint64) error {
	sc.Logger.Info("enabling runtime deployment",
		"runtime_id", rt.ID(),
		"deployment", deploymentIndex,
	)

	// Update the key manager policy.
	status, err := sc.KeyManagerStatus(ctx)
	if err != nil && err != secrets.ErrNoSuchStatus {
		return err
	}
	var policies map[sgx.EnclaveIdentity]*secrets.EnclavePolicySGX
	if status != nil && status.Policy != nil {
		policies = status.Policy.Policy.Enclaves
	}
	switch policies {
	case nil:
		sc.Logger.Info("no SGX runtimes, skipping policy update")
	default:
		sc.UpdateEnclavePolicies(rt, deploymentIndex, policies)
		if err = sc.ApplyKeyManagerPolicy(ctx, childEnv, cli, 0, policies, nonce); err != nil {
			return fmt.Errorf("updating policies: %w", err)
		}
		nonce++
	}

	// Fetch current epoch.
	epoch, err := sc.Net.Controller().Beacon.GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to get current epoch: %w", err)
	}

	// The upgrade epoch should be set to at least 4 to provide compute workers with enough time
	// to prepare for the upgrade. If it is set too low, the runtime will be suspended due to
	// a lack of eligible compute workers.
	upgradeEpoch := epoch + 4

	// Fetch old deployment.
	oldRtDsc, err := sc.Net.Controller().Registry.GetRuntime(ctx, &registry.GetRuntimeQuery{
		Height: consensus.HeightLatest,
		ID:     rt.ID(),
	})
	if err != nil {
		return fmt.Errorf("failed to get runtime descriptor: %w", err)
	}

	// Update runtime to include the new enclave identity.
	newRtDsc := rt.ToRuntimeDescriptor()
	newRtDpl := newRtDsc.Deployments[deploymentIndex]
	newRtDpl.ValidFrom = upgradeEpoch
	newRtDsc.Deployments = append(oldRtDsc.Deployments, newRtDpl)

	sc.Logger.Info("updating runtime descriptor",
		"runtime_id", rt.ID(),
		"version", newRtDpl.Version,
		"valid_from", newRtDpl.ValidFrom,
	)

	if err = sc.RegisterRuntime(childEnv, cli, newRtDsc, nonce); err != nil {
		return err
	}
	nonce++ // nolint: ineffassign

	// Wait for activation epoch.
	sc.Logger.Info("waiting for runtime upgrade epoch",
		"runtime_id", rt.ID(),
		"epoch", upgradeEpoch,
	)
	if err := sc.Net.Controller().Beacon.WaitEpoch(ctx, upgradeEpoch); err != nil {
		return fmt.Errorf("failed to wait for epoch: %w", err)
	}

	return nil
}

// UpgradeComputeRuntimeFixture select the first compute runtime and prepares it for the upgrade.
func (sc *Scenario) UpgradeComputeRuntimeFixture(f *oasis.NetworkFixture, excludeBundle bool) (int, error) {
	// Select the first compute runtime for upgrade.
	idx := -1
	for i := range f.Runtimes {
		if f.Runtimes[i].Kind == registry.KindCompute {
			idx = i
			break
		}
	}
	if idx == -1 {
		return 0, fmt.Errorf("expected at least one compute runtime in the fixture, none found")
	}

	// Load the upgraded runtime binary.
	newRuntimeBinaries := sc.ResolveRuntimeBinaries(KeyValueRuntimeUpgradeBinary)

	// Create a duplicate runtime, which will be added to the genesis.
	f.Runtimes = append(f.Runtimes, f.Runtimes[idx])

	// The original runtime will be excluded from the genesis and registered later.
	// Note that if the runtime bundles already exist (e.g. after the dump-restore upgrade),
	// they will be retained.
	f.Runtimes[idx].ExcludeFromGenesis = true
	f.Runtimes[idx].Deployments = append(f.Runtimes[idx].Deployments, oasis.DeploymentCfg{
		Components: []oasis.ComponentCfg{
			{
				Kind:     component.RONL,
				Version:  version.Version{Major: 0, Minor: 1, Patch: 0},
				Binaries: newRuntimeBinaries,
			},
		},
		ExcludeBundle: excludeBundle,
	})

	return idx, nil
}

// UpgradeComputeRuntime upgrades the specified compute runtime.
func (sc *Scenario) UpgradeComputeRuntime(ctx context.Context, childEnv *env.Env, cli *cli.Helpers, idx int, nonce uint64) error {
	newRt := sc.Net.Runtimes()[idx]

	// Make sure the old version is active on all compute nodes.
	if err := sc.EnsureActiveVersionForComputeWorkers(ctx, newRt.ID(), version.MustFromString("0.0.0")); err != nil {
		return err
	}

	// Transition to the new version.
	if err := sc.EnableRuntimeDeployment(ctx, childEnv, cli, newRt, 1, nonce); err != nil {
		return err
	}

	// Make sure the new version is active.
	return sc.EnsureActiveVersionForComputeWorkers(ctx, newRt.ID(), version.MustFromString("0.1.0"))
}

// UpgradeKeyManagerFixture select the first key manager runtime and prepares it for the upgrade.
func (sc *Scenario) UpgradeKeyManagerFixture(f *oasis.NetworkFixture, excludeBundle bool) (int, error) {
	// Select the first key manager for upgrade.
	idx := -1
	for i := range f.Runtimes {
		if f.Runtimes[i].Kind == registry.KindKeyManager {
			idx = i
			break
		}
	}
	if idx == -1 {
		return 0, fmt.Errorf("expected at least one key manager in the fixture, none found")
	}

	// Load the upgraded key manager binary.
	newRuntimeBinaries := sc.ResolveRuntimeBinaries(KeyManagerRuntimeUpgradeBinary)

	// Create a duplicate runtime, which will be added to the genesis latter.
	newRt := f.Runtimes[idx]
	newRt.ExcludeFromGenesis = true
	newRt.Deployments = []oasis.DeploymentCfg{
		{
			Components: []oasis.ComponentCfg{
				{
					Kind:     component.RONL,
					Version:  version.Version{Major: 0, Minor: 1, Patch: 0},
					Binaries: newRuntimeBinaries,
				},
			},
			ExcludeBundle: excludeBundle,
		},
	}
	f.Runtimes = append(f.Runtimes, newRt)

	// Keep the original runtime intact, and return index of the new one.
	idx = len(f.Runtimes) - 1

	// Add the upgraded key manager, which will be started later.
	f.Keymanagers = append(f.Keymanagers, oasis.KeymanagerFixture{
		NodeFixture: oasis.NodeFixture{
			NoAutoStart: true,
		},
		Runtime: idx,
		Entity:  1,
	})

	// Allow keymanager-0 to exit after replication is done.
	f.Keymanagers[0].AllowEarlyTermination = true

	return idx, nil
}

func (sc *Scenario) UpgradeKeyManager(ctx context.Context, childEnv *env.Env, cli *cli.Helpers, idx int, nonce uint64) error {
	oldKm := sc.Net.Keymanagers()[0]
	newKm := sc.Net.Keymanagers()[1]
	newRt := sc.Net.Runtimes()[idx]

	// Make sure the old version is active on the first key manager node.
	if err := sc.EnsureActiveVersionForKeyManager(ctx, oldKm, newRt.ID(), version.MustFromString("0.0.0")); err != nil {
		return err
	}

	// Transition to the new version.
	if err := sc.EnableRuntimeDeployment(ctx, childEnv, cli, newRt, 0, nonce); err != nil {
		return err
	}

	// Start the new keymanager.
	sc.Logger.Info("starting new keymanager")
	if err := newKm.Start(); err != nil {
		return fmt.Errorf("starting new key manager: %w", err)
	}

	// Wait for the new node to register.
	sc.Logger.Info("waiting for new keymanager node to register",
		"num_nodes", sc.Net.NumRegisterNodes(),
	)
	if err := newKm.WaitReady(ctx); err != nil {
		return fmt.Errorf("error waiting for new keymanager to be ready: %w", err)
	}

	// Ensure replication succeeded.
	if err := sc.ensureReplicationWorked(ctx, newKm, newRt); err != nil {
		return err
	}

	// Verify that both key managers can successfully register after the upgrade. If enclave
	// initialization no longer functions, for example, due to issues such as policy parsing,
	// consensus verification failures, or decoding errors, the key managers will re-register
	// with the last init response and the last attestation. Upon expiration of the latter,
	// any subsequent re-registration attempts will be unsuccessful, resulting in the removal
	// of the key manager from the committee.
	//
	// This verification may take a significant amount of time, as we need to await the expiration
	// of the last attestation.
	params, err := sc.Net.ClientController().Registry.ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return err
	}

	// Wait for the last successful attestation to expire.
	if _, err = sc.WaitBlocks(ctx, int(params.TEEFeatures.SGX.DefaultMaxAttestationAge)); err != nil {
		return err
	}

	// And a bit more so that the current epoch ends.
	if err = sc.WaitEpochs(ctx, 1); err != nil {
		return err
	}

	// Now check if both key managers still form the committee.
	status, err := sc.KeyManagerStatus(ctx)
	if err != nil {
		return err
	}
	if size := len(status.Nodes); size != 2 {
		return fmt.Errorf("key manager committee's size is not correct: expected 2, got %d", size)
	}

	// Shutdown old keymanager and make sure it de-registers.
	nodeCh, nodeSub, err := sc.Net.Controller().Registry.WatchNodes(ctx)
	if err != nil {
		return fmt.Errorf("failed to watch nodes: %w", err)
	}
	defer nodeSub.Close()

	sc.Logger.Info("shutting down old keymanager")

	if err := oldKm.RequestShutdown(ctx, true); err != nil {
		return fmt.Errorf("failed to request shutdown: %w", err)
	}

	// Ensure keymanager de-registers.
OUTER:
	for {
		select {
		case ev := <-nodeCh:
			if !ev.IsRegistration && ev.Node.ID.Equal(oldKm.NodeID) {
				break OUTER
			}
		case <-time.After(10 * time.Second):
			return fmt.Errorf("failed to wait for keymanager to de-register")
		}
	}

	// Make sure the new version is active on the second key manager node.
	return sc.EnsureActiveVersionForKeyManager(ctx, newKm, newRt.ID(), version.MustFromString("0.1.0"))
}

func (sc *Scenario) ensureReplicationWorked(ctx context.Context, km *oasis.Keymanager, rt *oasis.Runtime) error {
	ctrl, err := oasis.NewController(km.SocketPath())
	if err != nil {
		return err
	}
	node, err := ctrl.Registry.GetNode(
		ctx,
		&registry.IDQuery{
			ID: km.NodeID,
		},
	)
	if err != nil {
		return err
	}
	nodeRt := node.GetRuntime(rt.ID(), version.Version{Major: 0, Minor: 1, Patch: 0})
	if nodeRt == nil {
		return fmt.Errorf("node is missing keymanager runtime from descriptor")
	}
	var signedInitResponse secrets.SignedInitResponse
	if err = cbor.Unmarshal(nodeRt.ExtraInfo, &signedInitResponse); err != nil {
		return fmt.Errorf("failed to unmarshal replica extrainfo")
	}

	// Grab a state dump and ensure all keymanager nodes have a matching
	// checksum.
	doc, err := ctrl.Consensus.StateToGenesis(ctx, 0)
	if err != nil {
		return fmt.Errorf("failed to obtain consensus state: %w", err)
	}

	for _, status := range doc.KeyManager.Statuses {
		if !status.ID.Equal(&nodeRt.ID) {
			continue
		}
		if !status.IsInitialized {
			return fmt.Errorf("key manager failed to initialize")
		}
		if !bytes.Equal(status.Checksum, signedInitResponse.InitResponse.Checksum) {
			return fmt.Errorf("key manager failed to replicate, checksum mismatch")
		}
		return nil
	}
	return fmt.Errorf("consensus state missing km status")
}

func (sc *Scenario) WaitNextRuntimeBlock(ch <-chan *roothash.AnnotatedBlock) (*roothash.AnnotatedBlock, error) {
	sc.Logger.Info("waiting for next runtime block")

	timer := time.NewTimer(10 * time.Second)

	for {
		select {
		case blk, ok := <-ch:
			if !ok {
				return nil, fmt.Errorf("runtime block channel closed")
			}
			return blk, nil
		case <-timer.C:
			return nil, fmt.Errorf("failed to receive runtime block")
		}
	}
}

func (sc *Scenario) WaitRuntimeBlock(ch <-chan *roothash.AnnotatedBlock, round uint64) (*roothash.AnnotatedBlock, error) {
	sc.Logger.Info("waiting for runtime block",
		"round", round,
	)

	timer := time.NewTimer(10 * time.Second)

	for {
		select {
		case blk, ok := <-ch:
			if !ok {
				return nil, fmt.Errorf("runtime block channel closed")
			}
			sc.Logger.Info("new runtime block",
				"round", blk.Block.Header.Round,
			)
			if blk.Block.Header.Round > round {
				return nil, fmt.Errorf("runtime block round in the past")
			}
			if blk.Block.Header.Round < round {
				// Skip old rounds.
				continue
			}
			return blk, nil
		case <-timer.C:
			return nil, fmt.Errorf("failed to receive runtime block")
		}
	}
}
