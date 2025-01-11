package node

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	control "github.com/oasisprotocol/oasis-core/go/control/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

// Assert that the seed node implements NodeController interface.
var _ control.NodeController = (*SeedNode)(nil)

// RequestShutdown implements control.NodeController.
func (n *SeedNode) RequestShutdown(context.Context, bool) error {
	n.Stop()
	return nil
}

// WaitReady implements control.NodeController.
func (n *SeedNode) WaitReady(context.Context) error {
	return control.ErrNotImplemented
}

// IsReady implements control.NodeController.
func (n *SeedNode) IsReady(context.Context) (bool, error) {
	return false, control.ErrNotImplemented
}

// WaitSync implements control.NodeController.
func (n *SeedNode) WaitSync(context.Context) error {
	return control.ErrNotImplemented
}

// IsSynced implements control.NodeController.
func (n *SeedNode) IsSynced(context.Context) (bool, error) {
	return false, control.ErrNotImplemented
}

// UpgradeBinary implements control.NodeController.
func (n *SeedNode) UpgradeBinary(context.Context, *upgrade.Descriptor) error {
	return control.ErrNotImplemented
}

// CancelUpgrade implements control.NodeController.
func (n *SeedNode) CancelUpgrade(context.Context, *upgrade.Descriptor) error {
	return control.ErrNotImplemented
}

// GetStatus implements control.NodeController.
func (n *SeedNode) GetStatus(_ context.Context) (*control.Status, error) {
	tmAddresses, err := n.cometbftSeed.GetAddresses()
	if err != nil {
		return nil, err
	}
	libAddresses := n.libp2pSeed.Addresses()

	addresses := make([]string, 0)
	for _, addr := range tmAddresses {
		addresses = append(addresses, addr.String())
	}
	addresses = append(addresses, libAddresses...)

	seedStatus := control.SeedStatus{
		ChainContext: n.cometbftSeed.GetChainContext(),
		NodePeers:    append(n.cometbftSeed.GetPeers(), n.libp2pSeed.Peers()...),
		Addresses:    addresses,
	}

	identity := control.IdentityStatus{
		Node:      n.identity.NodeSigner.Public(),
		Consensus: n.identity.ConsensusSigner.Public(),
		TLS:       n.identity.TLSSigner.Public(),
	}

	return &control.Status{
		SoftwareVersion: version.SoftwareVersion,
		Mode:            config.GlobalConfig.Mode,
		Identity:        identity,
		Seed:            &seedStatus,
	}, nil
}
