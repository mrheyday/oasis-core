package tendermint

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/spf13/viper"
	tmlight "github.com/tendermint/tendermint/light"
	tmlightprovider "github.com/tendermint/tendermint/light/provider"
	tmlightdb "github.com/tendermint/tendermint/light/store/db"
	tmstate "github.com/tendermint/tendermint/state"
	tmstatesync "github.com/tendermint/tendermint/statesync"
	tmtypes "github.com/tendermint/tendermint/types"
	tmdb "github.com/tendermint/tm-db"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
)

// stateProviderConfig is the configuration for the state provider.
type stateProviderConfig struct {
	// ChainID is the Tendermint chain ID.
	ChainID string

	// ConsensusNodes is a list of nodes exposing the Oasis Core public consensus services that are
	// used to fetch data required for syncing light clients. The first node is considered the
	// primary and at least two nodes must be specified.
	ConsensusNodes []node.TLSAddress

	// TrustOptions are Tendermint light client trust options.
	TrustOptions tmlight.TrustOptions
}

type stateProvider struct {
	sync.Mutex

	ctx context.Context
	lc  *tmlight.Client

	logger *logging.Logger
}

// Implements tmstatesync.StateProvider.
func (sp *stateProvider) AppHash(height uint64) ([]byte, error) {
	sp.Lock()
	defer sp.Unlock()

	// We have to fetch the next height, which contains the app hash for the previous height.
	header, err := sp.lc.VerifyHeaderAtHeight(int64(height+1), time.Now())
	if err != nil {
		return nil, err
	}
	return header.AppHash, nil
}

// Implements tmstatesync.StateProvider.
func (sp *stateProvider) Commit(height uint64) (*tmtypes.Commit, error) {
	sp.Lock()
	defer sp.Unlock()

	header, err := sp.lc.VerifyHeaderAtHeight(int64(height), time.Now())
	if err != nil {
		return nil, err
	}
	return header.Commit, nil
}

// Implements tmstatesync.StateProvider.
func (sp *stateProvider) State(height uint64) (tmstate.State, error) {
	sp.Lock()
	defer sp.Unlock()

	state := tmstate.State{
		ChainID: sp.lc.ChainID(),
		Version: tmstate.InitStateVersion,
	}
	// XXX: This will fail in case an upgrade happened inbetween.
	state.Version.Consensus.App = version.ConsensusProtocol.ToU64()

	// We need to verify up until h+2, to get the validator set. This also prefetches the headers
	// for h and h+1 in the typical case where the trusted header is after the snapshot height.
	_, err := sp.lc.VerifyHeaderAtHeight(int64(height+2), time.Now())
	if err != nil {
		return tmstate.State{}, err
	}
	header, err := sp.lc.VerifyHeaderAtHeight(int64(height), time.Now())
	if err != nil {
		return tmstate.State{}, err
	}
	nextHeader, err := sp.lc.VerifyHeaderAtHeight(int64(height+1), time.Now())
	if err != nil {
		return tmstate.State{}, err
	}
	state.LastBlockHeight = header.Height
	state.LastBlockTime = header.Time
	state.LastBlockID = header.Commit.BlockID
	state.AppHash = nextHeader.AppHash
	state.LastResultsHash = nextHeader.LastResultsHash

	state.LastValidators, _, err = sp.lc.TrustedValidatorSet(int64(height))
	if err != nil {
		return tmstate.State{}, err
	}
	state.Validators, _, err = sp.lc.TrustedValidatorSet(int64(height + 1))
	if err != nil {
		return tmstate.State{}, err
	}
	state.NextValidators, _, err = sp.lc.TrustedValidatorSet(int64(height + 2))
	if err != nil {
		return tmstate.State{}, err
	}
	state.LastHeightValidatorsChanged = int64(height)

	// Fetch consensus parameters with light client verification.
	primaryClient := sp.lc.Primary().(*lightClientProvider).client
	ls, err := newLightService(primaryClient, sp.lc)
	if err != nil {
		return tmstate.State{}, fmt.Errorf("failed to create a new light service: %w", err)
	}
	params, err := ls.getParameters(sp.ctx, nextHeader.Height)
	if err != nil {
		return tmstate.State{}, fmt.Errorf("failed to fetch consensus parameters for height %d: %w",
			nextHeader.Height,
			err,
		)
	}
	state.ConsensusParams = *params

	return state, nil
}

func newStateProvider(ctx context.Context, cfg stateProviderConfig) (tmstatesync.StateProvider, error) {
	if numNodes := len(cfg.ConsensusNodes); numNodes < 2 {
		return nil, fmt.Errorf("at least two consensus nodes must be provided (got %d)", numNodes)
	}

	var providers []tmlightprovider.Provider
	for _, address := range cfg.ConsensusNodes {
		p, err := newLightClientProvider(ctx, cfg.ChainID, address)
		if err != nil {
			return nil, fmt.Errorf("failed to create light client provider: %w", err)
		}
		providers = append(providers, p)
	}

	lc, err := tmlight.NewClient(
		cfg.ChainID,
		cfg.TrustOptions,
		providers[0],  // Primary provider.
		providers[1:], // Witnesses.
		tmlightdb.New(tmdb.NewMemDB(), ""),
		tmlight.MaxRetryAttempts(5),
		tmlight.Logger(newLogAdapter(!viper.GetBool(cfgLogDebug))),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create light client: %w", err)
	}

	return &stateProvider{
		ctx:    ctx,
		lc:     lc,
		logger: logging.GetLogger("consensus/tendermint/stateprovider"),
	}, nil
}
