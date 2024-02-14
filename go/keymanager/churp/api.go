package churp

import (
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
)

const (
	// ModuleName is the module name for CHURP extension.
	ModuleName = "keymanager/churp"
)

var (
	// ErrNoSuchStatus is the error returned when a CHURP status does not exist.
	ErrNoSuchStatus = errors.New(ModuleName, 1, "keymanager: churp: no such status")

	// MethodCreate is the method name for creating a new CHURP instance.
	MethodCreate = transaction.NewMethodName(ModuleName, "Create", CreateRequest{})

	// MethodUpdate is the method name for CHURP updates.
	MethodUpdate = transaction.NewMethodName(ModuleName, "Update", UpdateRequest{})

	// Methods is the list of all methods supported by the CHURP extension.
	Methods = []transaction.MethodName{
		MethodCreate,
		MethodUpdate,
	}
)

const (
	// GasOpCreate is the gas operation identifier for creation costs.
	GasOpCreate transaction.Op = "create"
	// GasOpUpdate is the gas operation identifier for update costs.
	GasOpUpdate transaction.Op = "update"
)

// DefaultGasCosts are the "default" gas costs for operations.
var DefaultGasCosts = transaction.Costs{
	GasOpCreate: 1000,
	GasOpUpdate: 1000,
}

// DefaultConsensusParameters are the "default" consensus parameters.
var DefaultConsensusParameters = ConsensusParameters{
	GasCosts: DefaultGasCosts,
}

// NewCreateTx creates a new create transaction.
func NewCreateTx(nonce uint64, fee *transaction.Fee, req *CreateRequest) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodCreate, req)
}

// NewUpdateTx creates a new update transaction.
func NewUpdateTx(nonce uint64, fee *transaction.Fee, req *UpdateRequest) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodUpdate, req)
}