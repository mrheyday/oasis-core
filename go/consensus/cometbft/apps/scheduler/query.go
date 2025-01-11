package scheduler

import (
	"context"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/scheduler/state"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// Query is the scheduler query interface.
type Query interface {
	Validators(context.Context) ([]*scheduler.Validator, error)
	AllCommittees(context.Context) ([]*scheduler.Committee, error)
	KindsCommittees(context.Context, []scheduler.CommitteeKind) ([]*scheduler.Committee, error)
	Genesis(context.Context) (*scheduler.Genesis, error)
	ConsensusParameters(context.Context) (*scheduler.ConsensusParameters, error)
}

// QueryFactory is the scheduler query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// QueryAt returns the scheduler query interface for a specific height.
func (sf *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	state, err := schedulerState.NewImmutableState(ctx, sf.state, height)
	if err != nil {
		return nil, err
	}

	// Some queries need access to the registry to give useful responses.
	regState, err := registryState.NewImmutableState(ctx, sf.state, height)
	if err != nil {
		return nil, err
	}

	return &schedulerQuerier{state, regState}, nil
}

type schedulerQuerier struct {
	state    *schedulerState.ImmutableState
	regState *registryState.ImmutableState
}

func (sq *schedulerQuerier) Validators(ctx context.Context) ([]*scheduler.Validator, error) {
	vals, err := sq.state.CurrentValidators(ctx)
	if err != nil {
		return nil, err
	}

	ret := make([]*scheduler.Validator, 0, len(vals))
	for _, v := range vals {
		ret = append(ret, v)
	}

	return ret, nil
}

func (sq *schedulerQuerier) AllCommittees(ctx context.Context) ([]*scheduler.Committee, error) {
	return sq.state.AllCommittees(ctx)
}

func (sq *schedulerQuerier) KindsCommittees(ctx context.Context, kinds []scheduler.CommitteeKind) ([]*scheduler.Committee, error) {
	return sq.state.KindsCommittees(ctx, kinds)
}

func (sq *schedulerQuerier) ConsensusParameters(ctx context.Context) (*scheduler.ConsensusParameters, error) {
	return sq.state.ConsensusParameters(ctx)
}

func (app *schedulerApplication) QueryFactory() interface{} {
	return &QueryFactory{app.state}
}

// NewQueryFactory returns a new QueryFactory backed by the given state
// instance.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{state}
}
