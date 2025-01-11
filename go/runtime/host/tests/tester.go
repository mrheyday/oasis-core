// Package tests contains common tests for runtime host implementations.
package tests

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

const (
	// This needs to be large as some runtimes can take a long time to initialize due to remote
	// attestation taking a long time.
	recvTimeout = 120 * time.Second

	// Runtime is already started at this point so we can have a smaller timeout than above.
	recvAbortTimeout = 10 * time.Second
)

// mockMessageHandler is a mock message handler which only implements a small subset of methods.
type mockMessageHandler struct{}

// Implements host.RuntimeHandler.
func (h *mockMessageHandler) NewSubHandler(host.CompositeRuntime, *bundle.Component) (host.RuntimeHandler, error) {
	return nil, fmt.Errorf("method not supported")
}

// Implements host.RuntimeHandler.
func (h *mockMessageHandler) AttachRuntime(host.Runtime) error {
	return nil
}

// Implements host.RuntimeHandler.
func (h *mockMessageHandler) Handle(context.Context, *protocol.Body) (*protocol.Body, error) {
	return nil, fmt.Errorf("method not supported")
}

// TestCase is a test case descriptor.
type TestCase struct {
	// Name is a test name used with t.Run.
	Name string

	// Fn is the actual test function.
	Fn func(*testing.T, host.Config, host.Provisioner)
}

func TestProvisioner(
	t *testing.T,
	cfg host.Config,
	factory func() (host.Provisioner, error),
	extraTests []TestCase,
) {
	if testing.Verbose() {
		// Initialize logging to aid debugging.
		_ = logging.Initialize(os.Stdout, logging.FmtLogfmt, logging.LevelDebug, map[string]logging.Level{})
	}

	require := require.New(t)

	if cfg.MessageHandler == nil {
		cfg.MessageHandler = &mockMessageHandler{}
	}

	defaultTestCases := []TestCase{
		{"Basic", testBasic},
		{"Restart", testRestart},
	}
	testCases := append(defaultTestCases, extraTests...)

	for _, tc := range testCases {
		p, err := factory()
		require.NoError(err, "NewProvisioner")

		t.Run(tc.Name, func(t *testing.T) {
			tc.Fn(t, cfg, p)
		})
	}
}

func mockRuntimeKeyManagerStatusUpdateRequest() (*protocol.Body, error) {
	// Generate a dummy key manager status for tests.
	var keymanagerID common.Namespace
	if err := keymanagerID.UnmarshalHex("c000000000000000fffffffffffffffffffffffffffffffffffffffffffffffe"); err != nil {
		return nil, err
	}

	policy := secrets.PolicySGX{
		Serial:   1,
		Enclaves: map[sgx.EnclaveIdentity]*secrets.EnclavePolicySGX{},
	}
	sigPolicy := secrets.SignedPolicySGX{
		Policy: policy,
	}
	for _, signer := range keymanager.TestSigners[1:] {
		sig, err := signature.Sign(signer, secrets.PolicySGXSignatureContext, cbor.Marshal(policy))
		if err != nil {
			return nil, fmt.Errorf("failed to sign mock policy: %w", err)
		}

		sigPolicy.Signatures = append(sigPolicy.Signatures, *sig)
	}

	status := secrets.Status{
		ID:            keymanagerID,
		IsInitialized: true,
		IsSecure:      true,
		Generation:    1,
		RotationEpoch: 0,
		Checksum:      []byte{1, 2, 3},
		Nodes:         nil,
		Policy:        &sigPolicy,
		RSK:           nil,
	}

	return &protocol.Body{RuntimeKeyManagerStatusUpdateRequest: &protocol.RuntimeKeyManagerStatusUpdateRequest{
		Status: status,
	}}, nil
}

func testBasic(t *testing.T, cfg host.Config, p host.Provisioner) {
	require := require.New(t)

	r, err := p.NewRuntime(cfg)
	require.NoError(err, "NewRuntime")
	r.Start()

	evCh, sub := r.WatchEvents()
	defer sub.Close()

	// Wait for a successful start event.
	select {
	case ev := <-evCh:
		require.NotNil(ev.Started, "should have received a successful start event")
	case <-time.After(recvTimeout):
		t.Fatalf("Failed to receive start event")
	}

	// Test with a simple ping request.
	ctx, cancel := context.WithTimeout(context.Background(), recvTimeout)
	defer cancel()

	rsp, err := r.Call(ctx, &protocol.Body{RuntimePingRequest: &protocol.Empty{}})
	require.NoError(err, "Call")
	require.NotNil(rsp.Empty, "runtime response to RuntimePingRequest should return an Empty body")

	// FIXME: Remove or replace this call, as the mockMessageHandler cannot
	//        handle HostFetchConsensusBlockRequest.
	req, err := mockRuntimeKeyManagerStatusUpdateRequest()
	require.NoError(err, "mockKeyManagerStatusRequest")

	rsp, err = r.Call(ctx, req)
	require.NoError(err, "KeyManagerStatusRequest Call")
	require.NotNil(rsp.RuntimeKeyManagerStatusUpdateResponse, "runtime response to RuntimeKeyManagerStatusUpdate should return a RuntimeKeyManagerStatusUpdateResponse body")

	// Request the runtime to stop.
	r.Stop()

	// Wait for a stop event.
	select {
	case ev := <-evCh:
		require.NotNil(ev.Stopped, "should have received a stop event")
	case <-time.After(recvTimeout):
		t.Fatalf("Failed to receive stop event")
	}
}

func testRestart(t *testing.T, cfg host.Config, p host.Provisioner) {
	require := require.New(t)

	r, err := p.NewRuntime(cfg)
	require.NoError(err, "NewRuntime")
	r.Start()
	defer r.Stop()

	evCh, sub := r.WatchEvents()
	defer sub.Close()

	// Wait for a successful start event.
	select {
	case ev := <-evCh:
		require.NotNil(ev.Started, "should have received a successful start event")
	case <-time.After(recvTimeout):
		t.Fatalf("Failed to receive event")
	}

	// Trigger a force abort (should restart the runtime).
	// FIXME: Runtimes do not support abort requests anymore.
	err = r.Abort(context.Background(), true)
	require.NoError(err, "Abort(force=true)")

	// Wait for a stop event.
	select {
	case ev := <-evCh:
		require.NotNil(ev.Stopped, "should have received a stop event")
	case <-time.After(recvTimeout):
		t.Fatalf("Failed to receive stop event")
	}

	// Wait for a successful start event.
	select {
	case ev := <-evCh:
		require.NotNil(ev.Started, "should have received a successful start event")
	case <-time.After(recvTimeout):
		t.Fatalf("Failed to receive event")
	}

	// Trigger a non-force abort (runtime should not be restarted).
	err = r.Abort(context.Background(), false)
	require.NoError(err, "Abort(force=false)")

	// There should be no stop event.
	select {
	case ev := <-evCh:
		require.Nil(ev.Stopped, "unexpected stop event")
	case <-time.After(recvAbortTimeout):
	}

	// Trigger another non-force abort (runtime should not be restarted).
	// NOTE: the above Abort request makes it to the dispatcher before the first
	// iteration of the dispatch loop, therefore the request is handled before
	// the dispatcher is stuck in the recv loop. Here it is ensured that the
	// runtime dispatcher is already running and waiting on requests.
	err = r.Abort(context.Background(), false)
	require.NoError(err, "Abort(force=false)")

	// There should be no stop event.
	select {
	case ev := <-evCh:
		require.Nil(ev.Stopped, "unexpected stop event")
	case <-time.After(recvAbortTimeout):
	}
}
