package localbackend

import (
	"context"

	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/grpc/policy"
	"github.com/oasisprotocol/oasis-core/go/sentry/api"
)

// LocalBackend is a local sentry backend implementation.
type LocalBackend interface {
	api.Backend

	// GetPolicyChecker returns the current access policy checker for the given service.
	GetPolicyChecker(context.Context, cmnGrpc.ServiceName) (*policy.DynamicRuntimePolicyChecker, error)
}
