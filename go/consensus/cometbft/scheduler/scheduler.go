// Package scheduler implements the CometBFT backed scheduling backend.
package scheduler

import (
	"context"
	"fmt"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"
	cmtpubsub "github.com/cometbft/cometbft/libs/pubsub"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/events"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/scheduler"
	"github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// ServiceClient is the scheduler service client interface.
type ServiceClient interface {
	api.Backend
	tmapi.ServiceClient
}

type serviceClient struct {
	tmapi.BaseServiceClient

	logger *logging.Logger

	querier  *app.QueryFactory
	notifier *pubsub.Broker
}

func (sc *serviceClient) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, fmt.Errorf("scheduler: genesis query failed: %w", err)
	}
	return q.Genesis(ctx)
}

func (sc *serviceClient) ConsensusParameters(ctx context.Context, height int64) (*api.ConsensusParameters, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, fmt.Errorf("scheduler: genesis query failed: %w", err)
	}
	return q.ConsensusParameters(ctx)
}

func (sc *serviceClient) Cleanup() {
}

func (sc *serviceClient) GetValidators(ctx context.Context, height int64) ([]*api.Validator, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Validators(ctx)
}

func (sc *serviceClient) GetCommittees(ctx context.Context, request *api.GetCommitteesRequest) ([]*api.Committee, error) {
	q, err := sc.querier.QueryAt(ctx, request.Height)
	if err != nil {
		return nil, err
	}

	committees, err := q.AllCommittees(ctx)
	if err != nil {
		return nil, err
	}

	var runtimeCommittees []*api.Committee
	for _, c := range committees {
		if c.RuntimeID.Equal(&request.RuntimeID) {
			runtimeCommittees = append(runtimeCommittees, c)
		}
	}

	return runtimeCommittees, nil
}

func (sc *serviceClient) WatchCommittees(_ context.Context) (<-chan *api.Committee, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.Committee)
	sub := sc.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (sc *serviceClient) getCurrentCommittees() ([]*api.Committee, error) {
	q, err := sc.querier.QueryAt(context.TODO(), consensus.HeightLatest)
	if err != nil {
		return nil, err
	}

	return q.AllCommittees(context.TODO())
}

// Implements api.ServiceClient.
func (sc *serviceClient) ServiceDescriptor() tmapi.ServiceDescriptor {
	return tmapi.NewStaticServiceDescriptor(api.ModuleName, app.EventType, []cmtpubsub.Query{app.QueryApp})
}

// Implements api.ServiceClient.
func (sc *serviceClient) DeliverEvent(ctx context.Context, height int64, _ cmttypes.Tx, ev *cmtabcitypes.Event) error {
	for _, pair := range ev.GetAttributes() {
		if events.IsAttributeKind(pair.GetKey(), &api.ElectedEvent{}) {
			var e api.ElectedEvent
			if err := events.DecodeValue(pair.GetValue(), &e); err != nil {
				sc.logger.Error("worker: malformed elected committee types event",
					"err", err,
				)
				continue
			}

			q, err := sc.querier.QueryAt(ctx, height)
			if err != nil {
				sc.logger.Error("worker: couldn't query elected committees",
					"err", err,
				)
				continue
			}

			committees, err := q.KindsCommittees(ctx, e.Kinds)
			if err != nil {
				sc.logger.Error("worker: couldn't query elected committees",
					"err", err,
				)
				continue
			}

			for _, c := range committees {
				sc.notifier.Broadcast(c)
			}
		}
	}
	return nil
}

// New constructs a new CometBFT-based scheduler Backend instance.
func New(backend tmapi.Backend) (ServiceClient, error) {
	// Initialze and register the CometBFT service component.
	a := app.New()
	if err := backend.RegisterApplication(a); err != nil {
		return nil, err
	}

	sc := &serviceClient{
		logger:  logging.GetLogger("cometbft/scheduler"),
		querier: a.QueryFactory().(*app.QueryFactory),
	}
	sc.notifier = pubsub.NewBrokerEx(func(ch channels.Channel) {
		currentCommittees, err := sc.getCurrentCommittees()
		if err != nil {
			sc.logger.Error("couldn't get current committees. won't send them. good luck to the subscriber",
				"err", err,
			)
			return
		}
		for _, c := range currentCommittees {
			ch.In() <- c
		}
	})

	return sc, nil
}
