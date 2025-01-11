package churp

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
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

	// MethodApply is the method name for a node submitting an application
	// to form a new committee.
	MethodApply = transaction.NewMethodName(ModuleName, "Apply", ApplicationRequest{})

	// MethodConfirm is the method name for a node confirming completion
	// of a handoff.
	MethodConfirm = transaction.NewMethodName(ModuleName, "Confirm", ConfirmationRequest{})

	// Methods is the list of all methods supported by the CHURP extension.
	Methods = []transaction.MethodName{
		MethodCreate,
		MethodUpdate,
		MethodApply,
		MethodConfirm,
	}
)

const (
	// GasOpCreate is the gas operation identifier for creation costs.
	GasOpCreate transaction.Op = "create"
	// GasOpUpdate is the gas operation identifier for update costs.
	GasOpUpdate transaction.Op = "update"
	// GasOpApply is the gas operation identifier for application costs.
	GasOpApply transaction.Op = "apply"
	// GasOpConfirm is the gas operation identifier for confirmation costs.
	GasOpConfirm transaction.Op = "confirm"
)

// DefaultGasCosts are the "default" gas costs for operations.
var DefaultGasCosts = transaction.Costs{
	GasOpCreate:  1000,
	GasOpUpdate:  1000,
	GasOpApply:   1000,
	GasOpConfirm: 1000,
}

// DefaultConsensusParameters are the "default" consensus parameters.
var DefaultConsensusParameters = ConsensusParameters{
	GasCosts: DefaultGasCosts,
}

const (
	// StakeClaimScheme is the stake claim template used for creating
	// new CHURP schemes.
	StakeClaimScheme = "keymanager.churp.Scheme.%s.%d"
)

// StakeClaim generates a new stake claim identifier for a specific
// scheme creation.
func StakeClaim(runtimeID common.Namespace, churpID uint8) staking.StakeClaim {
	return staking.StakeClaim(fmt.Sprintf(StakeClaimScheme, runtimeID, churpID))
}

// StakeThresholds returns the staking thresholds.
func StakeThresholds() []staking.StakeThreshold {
	return staking.GlobalStakeThresholds(staking.KindKeyManagerChurp)
}

// NewCreateTx creates a new create transaction.
func NewCreateTx(nonce uint64, fee *transaction.Fee, req *CreateRequest) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodCreate, req)
}

// NewUpdateTx creates a new update transaction.
func NewUpdateTx(nonce uint64, fee *transaction.Fee, req *UpdateRequest) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodUpdate, req)
}

// NewApplyTx creates a new apply transaction.
func NewApplyTx(nonce uint64, fee *transaction.Fee, req *SignedApplicationRequest) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodApply, req)
}

// NewConfirmTx creates a new confirm transaction.
func NewConfirmTx(nonce uint64, fee *transaction.Fee, req *SignedConfirmationRequest) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodConfirm, req)
}

// StatusQuery is a status query by CHURP and runtime ID.
type StatusQuery struct {
	Height    int64            `json:"height"`
	RuntimeID common.Namespace `json:"runtime_id"`
	ChurpID   uint8            `json:"churp_id"`
}
