package committee

import (
	"context"
	"fmt"
	"sync"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/nodes"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

const (
	// tagExecutor is the committee node descriptor tag to use for executor nodes.
	tagExecutor = "executor"
)

// TagForCommittee returns node lookup tag for scheduler committee kind.
func TagForCommittee(kind scheduler.CommitteeKind) string {
	switch kind {
	case scheduler.KindComputeExecutor:
		return tagExecutor
	default:
		return ""
	}
}

// CommitteeInfo contains information about a committee of nodes.
type CommitteeInfo struct { // nolint: revive
	Indices    []int
	Roles      []scheduler.Role
	Committee  *scheduler.Committee
	PublicKeys map[signature.PublicKey]struct{}
	Peers      map[signature.PublicKey]struct{}
}

// HasRole checks whether the node has the given role.
func (ci *CommitteeInfo) HasRole(role scheduler.Role) bool {
	for _, r := range ci.Roles {
		if r == role {
			return true
		}
	}
	return false
}

type epoch struct {
	// epochNumber is the sequential number of the epoch.
	epochNumber beacon.EpochTime
	// epochHeight is the height at which the epoch transition happened.
	epochHeight int64

	// executorCommittee is the executor committee we are a member of.
	executorCommittee *CommitteeInfo

	runtime *registry.Runtime
}

// EpochSnapshot is an immutable snapshot of epoch state.
type EpochSnapshot struct {
	identity *identity.Identity

	epochNumber beacon.EpochTime
	epochHeight int64

	runtime *registry.Runtime

	executorCommittee *CommitteeInfo

	nodes nodes.VersionedNodeDescriptorWatcher
}

// IsValid checks whether the given epoch snapshot is valid (represents an actual epoch).
func (e *EpochSnapshot) IsValid() bool {
	return e.identity != nil
}

// GetRuntime returns the current runtime descriptor.
func (e *EpochSnapshot) GetRuntime() *registry.Runtime {
	return e.runtime
}

// GetExecutorCommittee returns the current executor committee.
func (e *EpochSnapshot) GetExecutorCommittee() *CommitteeInfo {
	return e.executorCommittee
}

// GetEpochNumber returns the sequential number of the epoch.
func (e *EpochSnapshot) GetEpochNumber() beacon.EpochTime {
	return e.epochNumber
}

// GetEpochHeight returns the consensus height corresponding to the epoch transition.
func (e *EpochSnapshot) GetEpochHeight() int64 {
	return e.epochHeight
}

// IsExecutorMember checks if the current node is a member of the executor committee
// in the current epoch.
func (e *EpochSnapshot) IsExecutorMember() bool {
	if e.executorCommittee == nil {
		return false
	}
	return len(e.executorCommittee.Roles) > 0
}

// IsExecutorWorker checks if the current node is a worker of the executor committee
// in the current epoch.
func (e *EpochSnapshot) IsExecutorWorker() bool {
	if e.executorCommittee == nil {
		return false
	}
	return e.executorCommittee.HasRole(scheduler.RoleWorker)
}

// IsExecutorBackupWorker checks if the current node is a backup worker of the executor
// committee in the current epoch.
func (e *EpochSnapshot) IsExecutorBackupWorker() bool {
	if e.executorCommittee == nil {
		return false
	}
	return e.executorCommittee.HasRole(scheduler.RoleBackupWorker)
}

// Nodes returns a node descriptor lookup interface.
func (e *EpochSnapshot) Nodes() nodes.NodeDescriptorLookup {
	return e.nodes
}

// Node looks up a node descriptor.
//
// Implements commitment.NodeLookup.
func (e *EpochSnapshot) Node(_ context.Context, id signature.PublicKey) (*node.Node, error) {
	n := e.nodes.Lookup(id)
	if n == nil {
		return nil, registry.ErrNoSuchNode
	}
	return n, nil
}

// Group encapsulates communication with a group of nodes in the runtime committees.
type Group struct {
	sync.RWMutex

	runtimeID common.Namespace
	identity  *identity.Identity

	consensus consensus.Backend

	activeEpoch *epoch
	// nodes is a node descriptor watcher for all nodes that are part of any of our committees.
	// TODO: Consider removing nodes.
	nodes nodes.VersionedNodeDescriptorWatcher

	logger *logging.Logger
}

// RoundTransition processes a round transition that just happened.
func (g *Group) RoundTransition() {
	g.Lock()
	defer g.Unlock()

	if g.activeEpoch == nil {
		return
	}
}

// Suspend processes a runtime suspension that just happened.
//
// Resumption will be processed as a regular epoch transition.
func (g *Group) Suspend() {
	g.Lock()
	defer g.Unlock()

	if g.activeEpoch == nil {
		return
	}

	// Invalidate current epoch.
	g.activeEpoch = nil
}

// EpochTransition processes an epoch transition that just happened.
func (g *Group) EpochTransition(ctx context.Context, height int64) error {
	g.Lock()
	defer g.Unlock()

	// Invalidate current epoch. In case we cannot process this transition,
	// this should cause the node to transition into NotReady and stay there
	// until the next epoch transition.
	g.activeEpoch = nil
	// Reset watched nodes.
	g.nodes.Reset()
	defer func() {
		// Make sure there are no unneeded watched nodes in case this method fails.
		if g.activeEpoch == nil {
			g.nodes.Reset()
		}
	}()

	// Request committees from scheduler.
	committees, err := g.consensus.Scheduler().GetCommittees(ctx, &scheduler.GetCommitteesRequest{
		RuntimeID: g.runtimeID,
		Height:    height,
	})
	if err != nil {
		return fmt.Errorf("group: failed to get committees: %w", err)
	}

	// Find the current committees.
	var executorCommittee *CommitteeInfo
	publicIdentity := g.identity.NodeSigner.Public()
	for _, cm := range committees {
		var (
			roles   []scheduler.Role
			indices []int
		)
		publicKeys := make(map[signature.PublicKey]struct{})
		peers := make(map[signature.PublicKey]struct{})
		for index, member := range cm.Members {
			publicKeys[member.PublicKey] = struct{}{}
			if member.PublicKey.Equal(publicIdentity) {
				roles = append(roles, member.Role)
				indices = append(indices, index)
			}

			// Start watching the member's node descriptor.
			var n *node.Node
			if n, err = g.nodes.WatchNodeWithTag(ctx, member.PublicKey, TagForCommittee(cm.Kind)); err != nil {
				return fmt.Errorf("group: failed to fetch node info: %w", err)
			}

			peers[n.P2P.ID] = struct{}{}
		}

		ci := &CommitteeInfo{
			Indices:    indices,
			Roles:      roles,
			Committee:  cm,
			PublicKeys: publicKeys,
			Peers:      peers,
		}

		switch cm.Kind {
		case scheduler.KindComputeExecutor:
			executorCommittee = ci
		}
	}
	if executorCommittee == nil {
		return fmt.Errorf("group: no executor committee")
	}

	// Fetch the new epoch.
	epochNumber, err := g.consensus.Beacon().GetEpoch(ctx, height)
	if err != nil {
		return err
	}
	epochHeight, err := g.consensus.Beacon().GetEpochBlock(ctx, epochNumber)
	if err != nil {
		return err
	}

	// Fetch current runtime descriptor.
	runtime, err := g.consensus.Registry().GetRuntime(ctx, &registry.GetRuntimeQuery{ID: g.runtimeID, Height: height})
	if err != nil {
		return err
	}

	// Freeze the committee.
	g.nodes.Freeze(height)

	// Update the current epoch.
	g.activeEpoch = &epoch{
		epochNumber:       epochNumber,
		epochHeight:       epochHeight,
		executorCommittee: executorCommittee,
		runtime:           runtime,
	}

	g.logger.Info("epoch transition complete",
		"epoch", epochNumber,
		"executor_roles", executorCommittee.Roles,
	)

	return nil
}

// GetEpochSnapshot returns a snapshot of the currently active epoch.
func (g *Group) GetEpochSnapshot() *EpochSnapshot {
	g.RLock()
	defer g.RUnlock()

	if g.activeEpoch == nil {
		return &EpochSnapshot{}
	}

	s := &EpochSnapshot{
		identity:          g.identity,
		epochNumber:       g.activeEpoch.epochNumber,
		epochHeight:       g.activeEpoch.epochHeight,
		runtime:           g.activeEpoch.runtime,
		executorCommittee: g.activeEpoch.executorCommittee,
		nodes:             g.nodes,
	}

	return s
}

// Start starts the group services.
func (g *Group) Start() error {
	return nil
}

// NewGroup creates a new group.
func NewGroup(
	ctx context.Context,
	runtimeID common.Namespace,
	identity *identity.Identity,
	consensus consensus.Backend,
) (*Group, error) {
	nw, err := nodes.NewVersionedNodeDescriptorWatcher(ctx, consensus)
	if err != nil {
		return nil, fmt.Errorf("group: failed to create node watcher: %w", err)
	}

	return &Group{
		runtimeID: runtimeID,
		identity:  identity,
		consensus: consensus,
		nodes:     nw,
		logger:    logging.GetLogger("worker/common/committee/group").With("runtime_id", runtimeID),
	}, nil
}
