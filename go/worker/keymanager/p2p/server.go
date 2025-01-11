package p2p

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
)

// KeyManager is the keymanager service interface.
type KeyManager interface {
	// CallEnclave calls the keymanager enclave with the provided data.
	CallEnclave(ctx context.Context, data []byte, kind enclaverpc.Kind) ([]byte, error)
}

type service struct {
	km KeyManager
}

func (s *service) HandleRequest(ctx context.Context, method string, body cbor.RawMessage) (interface{}, error) {
	enclaveRPCCount.With(prometheus.Labels{"method": method}).Inc()

	switch method {
	case MethodCallEnclave:
		var rq CallEnclaveRequest
		if err := cbor.Unmarshal(body, &rq); err != nil {
			return nil, rpc.ErrBadRequest
		}

		return s.handleCallEnclave(ctx, &rq)
	default:
		return nil, rpc.ErrMethodNotSupported
	}
}

func (s *service) handleCallEnclave(ctx context.Context, request *CallEnclaveRequest) (*CallEnclaveResponse, error) {
	data, err := s.km.CallEnclave(ctx, request.Data, request.Kind)
	if err != nil {
		return nil, err
	}
	return &CallEnclaveResponse{
		Data: data,
	}, nil
}

// NewServer creates a new keymanager protocol server.
func NewServer(chainContext string, runtimeID common.Namespace, km KeyManager) rpc.Server {
	initMetrics()

	return rpc.NewServer(protocol.NewRuntimeProtocolID(chainContext, runtimeID, KeyManagerProtocolID, KeyManagerProtocolVersion), &service{km})
}
