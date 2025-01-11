package oasis

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	kmCmd "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/keymanager"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	runtimeCfg "github.com/oasisprotocol/oasis-core/go/runtime/config"
	runtimeConfig "github.com/oasisprotocol/oasis-core/go/runtime/config"
	keymanagerConfig "github.com/oasisprotocol/oasis-core/go/worker/keymanager/config"
)

const (
	kmStatusFile = "keymanager_status.json"
	kmPolicyFile = "keymanager_policy.cbor"

	keymanagerIdentitySeedTemplate = "ekiden node keymanager %d"
)

// KeymanagerPolicy is an Oasis key manager policy document.
type KeymanagerPolicy struct {
	net *Network
	dir *env.Dir

	statusArgs []string

	runtime          *Runtime
	serial           int
	rotationInterval beacon.EpochTime
}

// KeymanagerPolicyCfg is an Oasis key manager policy document configuration.
type KeymanagerPolicyCfg struct {
	Runtime                      *Runtime
	Serial                       int
	MasterSecretRotationInterval beacon.EpochTime
}

func (pol *KeymanagerPolicy) provisionStatusArgs() []string {
	return pol.statusArgs
}

func (pol *KeymanagerPolicy) provision() error {
	// Policy signed with test keys.
	policyPath := filepath.Join(pol.dir.String(), kmPolicyFile)
	policyArgs := []string{
		"keymanager", "init_policy",
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + kmCmd.CfgPolicyFile, policyPath,
		"--" + kmCmd.CfgPolicyID, pol.runtime.ID().String(),
		"--" + kmCmd.CfgPolicySerial, strconv.Itoa(pol.serial),
		"--" + kmCmd.CfgPolicyMasterSecretRotationInterval, strconv.FormatUint(uint64(pol.rotationInterval), 10),
	}
	if pol.runtime.teeHardware == node.TEEHardwareIntelSGX {
		policyArgs = append(policyArgs, []string{
			"--" + kmCmd.CfgPolicyEnclaveID, pol.runtime.GetEnclaveIdentity(0).String(),
		}...)
	}

	for _, rt := range pol.net.runtimes {
		if rt.teeHardware != node.TEEHardwareIntelSGX || rt.kind != registry.KindCompute {
			continue
		}

		arg := fmt.Sprintf("%s=%s", rt.ID(), rt.GetEnclaveIdentity(0))
		policyArgs = append(policyArgs, "--"+kmCmd.CfgPolicyMayQuery, arg)
	}

	w, err := pol.dir.NewLogWriter("provision-policy.log")
	if err != nil {
		return err
	}
	defer w.Close()

	if err = pol.net.runNodeBinary(w, policyArgs...); err != nil {
		pol.net.logger.Error("failed to provision keymanager policy",
			"err", err,
		)
		return fmt.Errorf("oasis/keymanager: failed to provision keymanager policy: %w", err)
	}

	// Sign policy with test keys.
	signArgsTpl := []string{
		"keymanager", "sign_policy",
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + kmCmd.CfgPolicyFile, policyPath,
	}
	for i := 1; i <= 3; i++ {
		signatureFile := filepath.Join(pol.dir.String(), fmt.Sprintf("%s.sign.%d", kmPolicyFile, i))
		signArgs := append([]string{}, signArgsTpl...)
		signArgs = append(signArgs, []string{
			"--" + kmCmd.CfgPolicySigFile, signatureFile,
			"--" + kmCmd.CfgPolicyTestKey, fmt.Sprintf("%d", i),
		}...)
		pol.statusArgs = append(pol.statusArgs, "--"+kmCmd.CfgPolicySigFile, signatureFile)

		w, err := pol.dir.NewLogWriter("provision-policy-sign.log")
		if err != nil {
			return err
		}
		defer w.Close()

		if err = pol.net.runNodeBinary(w, signArgs...); err != nil {
			pol.net.logger.Error("failed to sign keymanager policy",
				"err", err,
			)
			return fmt.Errorf("oasis/keymanager: failed to sign keymanager policy: %w", err)
		}
	}

	pol.statusArgs = append(pol.statusArgs, "--"+kmCmd.CfgPolicyFile, policyPath)

	return nil
}

// NewKeymanagerPolicy provisions a new keymanager policy and adds it to the
// network.
func (net *Network) NewKeymanagerPolicy(cfg *KeymanagerPolicyCfg) (*KeymanagerPolicy, error) {
	policyName := fmt.Sprintf("keymanager-policy-%d", cfg.Serial)

	policyDir, err := net.baseDir.NewSubDir(policyName)
	if err != nil {
		net.logger.Error("failed to create keymanager policy subdir",
			"err", err,
		)
		return nil, fmt.Errorf("oasis/keymanager: failed to create keymanager policy subdir: %w", err)
	}

	newPol := &KeymanagerPolicy{
		net:              net,
		dir:              policyDir,
		runtime:          cfg.Runtime,
		serial:           cfg.Serial,
		rotationInterval: cfg.MasterSecretRotationInterval,
	}
	net.keymanagerPolicies = append(net.keymanagerPolicies, newPol)

	return newPol, nil
}

// Keymanager is an Oasis key manager.
type Keymanager struct { // nolint: maligned
	*Node

	sentryIndices []int

	runtime            *Runtime
	policy             *KeymanagerPolicy
	runtimeProvisioner runtimeConfig.RuntimeProvisioner

	sentryPubKey  signature.PublicKey
	consensusPort uint16
	p2pPort       uint16

	privatePeerPubKeys []string
	churpIDs           []uint8
}

// KeymanagerCfg is the Oasis key manager provisioning configuration.
type KeymanagerCfg struct {
	NodeCfg

	SentryIndices []int

	Runtime            *Runtime
	Policy             *KeymanagerPolicy
	RuntimeProvisioner runtimeConfig.RuntimeProvisioner

	// PrivatePeerPubKeys is a list of base64-encoded libp2p public keys of peers who may call non-public methods.
	PrivatePeerPubKeys []string

	// ChurpIDs is a list of supported CHURP schemes.
	ChurpIDs []uint8
}

// IdentityKeyPath returns the paths to the node's identity key.
func (km *Keymanager) IdentityKeyPath() string {
	return nodeIdentityKeyPath(km.dir)
}

// P2PKeyPath returns the paths to the node's P2P key.
func (km *Keymanager) P2PKeyPath() string {
	return nodeP2PKeyPath(km.dir)
}

// ConsensusKeyPath returns the path to the node's consensus key.
func (km *Keymanager) ConsensusKeyPath() string {
	return nodeConsensusKeyPath(km.dir)
}

// TLSKeyPath returns the path to the node's TLS key.
func (km *Keymanager) TLSKeyPath() string {
	return nodeTLSKeyPath(km.dir)
}

// TLSCertPath returns the path to the node's TLS certificate.
func (km *Keymanager) TLSCertPath() string {
	return nodeTLSCertPath(km.dir)
}

// ExportsPath returns the path to the node's exports data dir.
func (km *Keymanager) ExportsPath() string {
	return nodeExportsPath(km.dir)
}

// P2PPort returns the node's P2P port.
func (km *Keymanager) P2PPort() uint16 {
	return km.p2pPort
}

func (km *Keymanager) provisionGenesis() error {
	if km.runtime.excludeFromGenesis {
		return nil
	}

	// Provision status. We can only provision this here as we need
	// a list of runtimes allowed to query the key manager.
	statusArgs := []string{
		"keymanager", "init_status",
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + kmCmd.CfgStatusID, km.runtime.ID().String(),
		"--" + kmCmd.CfgStatusFile, filepath.Join(km.dir.String(), kmStatusFile),
	}
	if km.policy != nil {
		statusArgs = append(statusArgs, km.policy.provisionStatusArgs()...)
	}

	w, err := km.dir.NewLogWriter("provision-status.log")
	if err != nil {
		return err
	}
	defer w.Close()

	if err = km.net.runNodeBinary(w, statusArgs...); err != nil {
		km.net.logger.Error("failed to provision keymanager status",
			"err", err,
		)
		return fmt.Errorf("oasis/keymanager: failed to provision keymanager status: %w", err)
	}

	return nil
}

func (km *Keymanager) toGenesisArgs() []string {
	if km.runtime.excludeFromGenesis {
		return nil
	}

	return []string{
		"--keymanager", filepath.Join(km.dir.String(), kmStatusFile),
	}
}

func (km *Keymanager) AddArgs(args *argBuilder) error {
	args.
		configureDebugCrashPoints(km.crashPointsProbability).
		appendNetwork(km.net)

	if km.entity.isDebugTestEntity {
		args.appendDebugTestEntity()
	}

	return nil
}

func (km *Keymanager) ModifyConfig() error {
	km.Config.Consensus.ListenAddress = allInterfacesAddr + ":" + strconv.Itoa(int(km.consensusPort))
	km.Config.Consensus.ExternalAddress = localhostAddr + ":" + strconv.Itoa(int(km.consensusPort))

	if km.supplementarySanityInterval > 0 {
		km.Config.Consensus.SupplementarySanity.Enabled = true
		km.Config.Consensus.SupplementarySanity.Interval = km.supplementarySanityInterval
	}

	km.Config.P2P.Port = km.p2pPort

	if !km.entity.isDebugTestEntity {
		entityID, _ := km.entity.ID().MarshalText() // Cannot fail.
		km.Config.Registration.EntityID = string(entityID)
	}

	km.Config.Mode = config.ModeKeyManager
	km.Config.Runtime.Provisioner = km.runtimeProvisioner
	km.Config.Runtime.SGXLoader = km.net.cfg.RuntimeSGXLoaderBinary
	km.Config.Runtime.AttestInterval = km.net.cfg.RuntimeAttestInterval

	rtCfg := runtimeCfg.RuntimeConfig{
		ID: km.runtime.cfgSave.id,
	}

	km.Config.Runtime.Runtimes = append(km.Config.Runtime.Runtimes, rtCfg)
	km.Config.Runtime.Paths = append(km.Config.Runtime.Paths, km.runtime.BundlePaths()...)
	km.Config.Runtime.Registries = []string{fmt.Sprintf("http://127.0.0.1:%d", km.net.getProvisionedPort(netPortRegistry))}

	km.Config.Keymanager.RuntimeID = km.runtime.ID().String()
	km.Config.Keymanager.PrivatePeerPubKeys = km.privatePeerPubKeys

	// Configuration for the CHURP key manager extension.
	schemes := make([]keymanagerConfig.ChurpSchemeConfig, len(km.churpIDs))
	for i, id := range km.churpIDs {
		schemes[i] = keymanagerConfig.ChurpSchemeConfig{
			ID: id,
		}
	}
	km.Config.Keymanager.Churp.Schemes = schemes

	// Sentry configuration.
	sentries, err := resolveSentries(km.net, km.sentryIndices)
	if err != nil {
		return err
	}

	if len(sentries) > 0 {
		km.Config.Consensus.P2P.DisablePeerExchange = true
		km.AddSentriesToConfig(sentries)
	} else {
		km.AddSeedNodesToConfig()
	}

	return nil
}

// NewKeymanager provisions a new keymanager and adds it to the network.
func (net *Network) NewKeymanager(cfg *KeymanagerCfg) (*Keymanager, error) {
	kmName := fmt.Sprintf("keymanager-%d", len(net.keymanagers))
	host, err := net.GetNamedNode(kmName, &cfg.NodeCfg)
	if err != nil {
		return nil, err
	}

	// Pre-provision the node identity so that we can update the entity.
	err = host.setProvisionedIdentity(fmt.Sprintf(keymanagerIdentitySeedTemplate, len(net.keymanagers)))
	if err != nil {
		return nil, fmt.Errorf("oasis/keymanager: failed to provision node identity: %w", err)
	}
	// Sentry client cert.
	pk, ok := host.sentryCert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("oasis/keymanager: bad sentry client public key type (expected: Ed25519 got: %T)", host.sentryCert.PublicKey)
	}
	var sentryPubKey signature.PublicKey
	if err := sentryPubKey.UnmarshalBinary(pk[:]); err != nil {
		return nil, fmt.Errorf("oasis/keymanager: sentry client public key unmarshal failure: %w", err)
	}

	if cfg.RuntimeProvisioner == "" {
		cfg.RuntimeProvisioner = runtimeConfig.RuntimeProvisionerSandboxed
	}

	km := &Keymanager{
		Node:               host,
		runtime:            cfg.Runtime,
		policy:             cfg.Policy,
		runtimeProvisioner: cfg.RuntimeProvisioner,
		sentryIndices:      cfg.SentryIndices,
		sentryPubKey:       sentryPubKey,
		consensusPort:      host.getProvisionedPort(nodePortConsensus),
		p2pPort:            host.getProvisionedPort(nodePortP2P),
		privatePeerPubKeys: cfg.PrivatePeerPubKeys,
		churpIDs:           cfg.ChurpIDs,
	}

	// Remove any exploded bundles on cleanup.
	net.env.AddOnCleanup(func() {
		_ = os.RemoveAll(bundle.ExplodedPath(km.dir.String()))
	})

	net.keymanagers = append(net.keymanagers, km)
	host.features = append(host.features, km)

	return km, nil
}
