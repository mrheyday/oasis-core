package tendermint

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"

	tmlight "github.com/tendermint/tendermint/light"
	tmlightprovider "github.com/tendermint/tendermint/light/provider"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
)

// lightClientProvider implements Tendermint's light client provider interface using the Oasis Core
// light client API.
type lightClientProvider struct {
	ctx context.Context

	chainID string
	client  consensusAPI.LightClientBackend
}

// Implements tmlightprovider.Provider.
func (lp *lightClientProvider) ChainID() string {
	return lp.chainID
}

// Implements tmlightprovider.Provider.
func (lp *lightClientProvider) SignedHeader(height int64) (*tmtypes.SignedHeader, error) {
	shdr, err := lp.client.GetSignedHeader(lp.ctx, height)
	switch {
	case err == nil:
	case errors.Is(err, consensusAPI.ErrVersionNotFound):
		return nil, tmlightprovider.ErrSignedHeaderNotFound
	default:
		return nil, fmt.Errorf("failed to fetch signed header: %w", err)
	}

	// Decode Tendermint-specific signed header.
	var protoSigHdr tmproto.SignedHeader
	if err = protoSigHdr.Unmarshal(shdr.Meta); err != nil {
		return nil, fmt.Errorf("received malformed header: %w", err)
	}
	sh, err := tmtypes.SignedHeaderFromProto(&protoSigHdr)
	if err != nil {
		return nil, fmt.Errorf("received malformed header: %w", err)
	}

	if lp.chainID != sh.ChainID {
		return nil, fmt.Errorf("incorrect chain ID (expected: %s got: %s)",
			lp.chainID,
			sh.ChainID,
		)
	}

	return sh, nil
}

// Implements tmlightprovider.Provider.
func (lp *lightClientProvider) ValidatorSet(height int64) (*tmtypes.ValidatorSet, error) {
	vs, err := lp.client.GetValidatorSet(lp.ctx, height)
	switch {
	case err == nil:
	case errors.Is(err, consensusAPI.ErrVersionNotFound):
		return nil, tmlightprovider.ErrValidatorSetNotFound
	default:
		return nil, fmt.Errorf("failed to fetch validator set: %w", err)
	}

	// Decode Tendermint-specific validator set.
	var protoVals tmproto.ValidatorSet
	if err = protoVals.Unmarshal(vs.Meta); err != nil {
		return nil, fmt.Errorf("received malformed validator set: %w", err)
	}
	vals, err := tmtypes.ValidatorSetFromProto(&protoVals)
	if err != nil {
		return nil, fmt.Errorf("received malformed validator set: %w", err)
	}

	return vals, nil
}

// Implements tmlightprovider.Provider.
func (lp *lightClientProvider) ReportEvidence(ev tmtypes.Evidence) error {
	// TODO: Implement SubmitEvidence.
	return fmt.Errorf("not yet implemented")
}

// newLightClientProvider creates a new provider for the Tendermint's light client.
//
// The provided chain ID must be the Tendermint chain ID.
func newLightClientProvider(
	ctx context.Context,
	chainID string,
	address node.TLSAddress,
) (tmlightprovider.Provider, error) {
	// Create TLS credentials.
	opts := cmnGrpc.ClientOptions{
		CommonName: identity.CommonName,
		ServerPubKeys: map[signature.PublicKey]bool{
			address.PubKey: true,
		},
	}
	creds, err := cmnGrpc.NewClientCreds(&opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS client credentials: %w", err)
	}

	conn, err := cmnGrpc.Dial(address.Address.String(), grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to dial public consensus service endpoint %s: %w", address, err)
	}

	return &lightClientProvider{
		ctx:     ctx,
		chainID: chainID,
		client:  consensusAPI.NewConsensusLightClient(conn),
	}, nil
}

// lightService is a Tendermint consensus service that uses the light client API to talk with a
// remote Tendermint node and verify responses.
//
// This should eventually become a replacement for the full node tendermintService.
type lightService struct {
	// lc is the Tendermint light client used for verifying headers.
	lc *tmlight.Client
	// client is the consensus light client backend connected to a remote node.
	client consensusAPI.LightClientBackend
}

func (ls *lightService) getParameters(ctx context.Context, height int64) (*tmproto.ConsensusParams, error) {
	p, err := ls.client.GetParameters(ctx, height)
	if err != nil {
		return nil, err
	}
	if p.Height <= 0 {
		return nil, fmt.Errorf("malformed height in response: %d", p.Height)
	}

	// Decode Tendermint-specific parameters.
	var params tmproto.ConsensusParams
	if err = params.Unmarshal(p.Meta); err != nil {
		return nil, fmt.Errorf("malformed parameters: %w", err)
	}
	if err = tmtypes.ValidateConsensusParams(params); err != nil {
		return nil, fmt.Errorf("malformed parameters: %w", err)
	}

	// Fetch the header from the light client.
	h, err := ls.lc.VerifyHeaderAtHeight(p.Height, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch header %d from light client: %w", p.Height, err)
	}

	// Verify hash.
	if localHash := tmtypes.HashConsensusParams(params); !bytes.Equal(localHash, h.ConsensusHash) {
		return nil, fmt.Errorf("mismatched parameters hash (expected: %X got: %X)",
			h.ConsensusHash,
			localHash,
		)
	}

	return &params, nil
}

// newLightService creates a light Tendermint consensus service.
func newLightService(client consensusAPI.LightClientBackend, lc *tmlight.Client) (*lightService, error) {
	return &lightService{
		lc:     lc,
		client: client,
	}, nil
}
