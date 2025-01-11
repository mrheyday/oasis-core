// Package mock implements a mock runtime host useful for tests.
package mock

import (
	"bytes"
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	mkvsNode "github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

type provisioner struct{}

// CheckTxFailInput is the input that will cause a CheckTx failure in the mock runtime.
var CheckTxFailInput = []byte("checktx-mock-fail")

// Implements host.Provisioner.
func (p *provisioner) NewRuntime(cfg host.Config) (host.Runtime, error) {
	r := &runtime{
		runtimeID: cfg.ID,
		notifier:  pubsub.NewBroker(false),
	}
	return r, nil
}

// Implements host.Provisioner.
func (p *provisioner) Name() string {
	return "mock"
}

type runtime struct {
	runtimeID common.Namespace

	notifier *pubsub.Broker
}

// Implements host.Runtime.
func (r *runtime) ID() common.Namespace {
	return r.runtimeID
}

// Implements host.Runtime.
func (r *runtime) GetInfo(context.Context) (*protocol.RuntimeInfoResponse, error) {
	return &protocol.RuntimeInfoResponse{
		ProtocolVersion: version.RuntimeHostProtocol,
		RuntimeVersion:  version.MustFromString("0.0.0"),
		Features: protocol.Features{
			ScheduleControl: &protocol.FeatureScheduleControl{
				InitialBatchSize: 100,
			},
		},
	}, nil
}

// Implements host.Runtime.
func (r *runtime) GetActiveVersion() (*version.Version, error) {
	return nil, nil
}

// Implements host.Runtime.
func (r *runtime) GetCapabilityTEE() (*node.CapabilityTEE, error) {
	return nil, nil
}

// Implements host.Runtime.
func (r *runtime) Call(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	switch {
	case body.RuntimeExecuteTxBatchRequest != nil:
		rq := body.RuntimeExecuteTxBatchRequest

		tags := transaction.Tags{
			&transaction.Tag{Key: []byte("txn_foo"), Value: []byte("txn_bar")},
		}

		emptyRoot := mkvsNode.Root{
			Namespace: rq.Block.Header.Namespace,
			Version:   rq.Block.Header.Round + 1,
			Type:      mkvsNode.RootTypeIO,
		}
		emptyRoot.Hash.Empty()

		tree := transaction.NewTree(nil, emptyRoot)
		defer tree.Close()

		// Generate input root.
		var txHashes []hash.Hash
		for _, tx := range rq.Inputs {
			err := tree.AddTransaction(ctx, transaction.Transaction{
				Input: tx,
			}, tags)
			if err != nil {
				return nil, fmt.Errorf("(mock) failed to create I/O tree: %w", err)
			}

			txHashes = append(txHashes, hash.NewFromBytes(tx))
		}
		txInputWriteLog, txInputRoot, err := tree.Commit(ctx)
		if err != nil {
			return nil, fmt.Errorf("(mock) failed to create I/O tree: %w", err)
		}

		// Generate outputs.
		for _, tx := range rq.Inputs {
			err = tree.AddTransaction(ctx, transaction.Transaction{
				Input:  tx,
				Output: tx,
			}, tags)
			if err != nil {
				return nil, fmt.Errorf("(mock) failed to create I/O tree: %w", err)
			}
		}
		ioWriteLog, ioRoot, err := tree.Commit(ctx)
		if err != nil {
			return nil, fmt.Errorf("(mock) failed to create I/O tree: %w", err)
		}

		var stateRoot, msgsHash, inMsgsHash hash.Hash
		stateRoot.Empty()
		msgsHash.Empty()
		inMsgsHash.Empty()

		return &protocol.Body{RuntimeExecuteTxBatchResponse: &protocol.RuntimeExecuteTxBatchResponse{
			Batch: protocol.ComputedBatch{
				Header: commitment.ComputeResultsHeader{
					Round:          rq.Block.Header.Round + 1,
					PreviousHash:   rq.Block.Header.EncodedHash(),
					IORoot:         &ioRoot,
					StateRoot:      &stateRoot,
					MessagesHash:   &msgsHash,
					InMessagesHash: &inMsgsHash,
				},
				IOWriteLog: ioWriteLog,
			},
			TxHashes:        txHashes,
			TxInputRoot:     txInputRoot,
			TxInputWriteLog: txInputWriteLog,
			// No RakSig in mock response.
		}}, nil
	case body.RuntimeCheckTxBatchRequest != nil:
		rq := body.RuntimeCheckTxBatchRequest

		var results []protocol.CheckTxResult
		for _, input := range rq.Inputs {
			switch {
			case bytes.Equal(input, CheckTxFailInput):
				results = append(results, protocol.CheckTxResult{
					Error: protocol.Error{
						Module: "mock",
						Code:   1,
					},
				})
			default:
				results = append(results, protocol.CheckTxResult{
					Error: protocol.Error{
						Code: errors.CodeNoError,
					},
				})
			}
		}

		return &protocol.Body{RuntimeCheckTxBatchResponse: &protocol.RuntimeCheckTxBatchResponse{
			Results: results,
		}}, nil
	case body.RuntimeQueryRequest != nil:
		rq := body.RuntimeQueryRequest

		switch rq.Method {
		default:
			return &protocol.Body{RuntimeQueryResponse: &protocol.RuntimeQueryResponse{
				Data: cbor.Marshal(rq.Method + " world at:" + fmt.Sprintf("%d", rq.ConsensusBlock.Height)),
			}}, nil
		}
	case body.RuntimeConsensusSyncRequest != nil:
		// Nothing to be done, but we need to indicate success.
		return &protocol.Body{RuntimeConsensusSyncResponse: &protocol.Empty{}}, nil
	default:
		return nil, fmt.Errorf("(mock) method not supported")
	}
}

// Implements host.Runtime.
func (r *runtime) UpdateCapabilityTEE() {
}

// Implements host.Runtime.
func (r *runtime) WatchEvents() (<-chan *host.Event, pubsub.ClosableSubscription) {
	typedCh := make(chan *host.Event)
	sub := r.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

// Implements host.Runtime.
func (r *runtime) Start() {
	r.notifier.Broadcast(&host.Event{
		Started: &host.StartedEvent{},
	})
}

// Implements host.Runtime.
func (r *runtime) Abort(context.Context, bool) error {
	return nil
}

// Implements host.Runtime.
func (r *runtime) Stop() {
	r.notifier.Broadcast(&host.Event{
		Stopped: &host.StoppedEvent{},
	})
}

// New creates a new mock runtime provisioner useful for tests.
func New() host.Provisioner {
	return &provisioner{}
}
