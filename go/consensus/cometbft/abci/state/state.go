package state

import (
	"context"
	"errors"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

var (
	// chainContextKeyFmt is the key format used for storing the chain context.
	//
	// Value is the chain context.
	chainContextKeyFmt = consensus.KeyFormat.New(0xF0)
	// parametersKeyFmt is the key format used for consensus parameters.
	//
	// Value is CBOR-serialized consensusGenesis.Parameters.
	parametersKeyFmt = consensus.KeyFormat.New(0xF1)
)

// ImmutableState is an immutable consensus backend state wrapper.
type ImmutableState struct {
	is *api.ImmutableState
}

// NewImmutableState creates a new immutable consensus backend state wrapper.
func NewImmutableState(ctx context.Context, state api.ApplicationQueryState, version int64) (*ImmutableState, error) {
	is, err := api.NewImmutableState(ctx, state, version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{is}, nil
}

// ChainContext returns the stored chain context.
func (s *ImmutableState) ChainContext(ctx context.Context) (string, error) {
	chainContext, err := s.is.Get(ctx, chainContextKeyFmt.Encode())
	if err != nil {
		return "", api.UnavailableStateError(err)
	}
	return string(chainContext), nil
}

// ConsensusParameters returns the consensus parameters.
func (s *ImmutableState) ConsensusParameters(ctx context.Context) (*consensusGenesis.Parameters, error) {
	raw, err := s.is.Get(ctx, parametersKeyFmt.Encode())
	if err != nil {
		return nil, api.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, errors.New("state: expected consensus parameters to be present in app state")
	}

	var params consensusGenesis.Parameters
	if err := cbor.Unmarshal(raw, &params); err != nil {
		return nil, api.UnavailableStateError(err)
	}
	return &params, nil
}

// MutableState is a mutable consensus backend state wrapper.
type MutableState struct {
	*ImmutableState

	ms mkvs.KeyValueTree
}

// SetChainContext sets the chain context.
//
// NOTE: This method must only be called from InitChain context.
func (s *MutableState) SetChainContext(ctx context.Context, chainContext string) error {
	if err := s.is.CheckContextMode(ctx, []api.ContextMode{api.ContextInitChain}); err != nil {
		return err
	}
	err := s.ms.Insert(ctx, chainContextKeyFmt.Encode(), []byte(chainContext))
	return api.UnavailableStateError(err)
}

// SetConsensusParameters sets the consensus parameters.
//
// NOTE: This method must only be called from InitChain/EndBlock contexts.
func (s *MutableState) SetConsensusParameters(ctx context.Context, params *consensusGenesis.Parameters) error {
	if err := s.is.CheckContextMode(ctx, []api.ContextMode{api.ContextInitChain, api.ContextEndBlock}); err != nil {
		return err
	}
	err := s.ms.Insert(ctx, parametersKeyFmt.Encode(), cbor.Marshal(params))
	return api.UnavailableStateError(err)
}

// NewMutableState creates a new mutable consensus backend state wrapper.
func NewMutableState(tree mkvs.KeyValueTree) *MutableState {
	return &MutableState{
		ImmutableState: &ImmutableState{
			&api.ImmutableState{ImmutableKeyValueTree: tree},
		},
		ms: tree,
	}
}
