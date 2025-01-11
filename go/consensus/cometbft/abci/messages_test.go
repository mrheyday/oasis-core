package abci

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
)

type testMessageKind uint8

var (
	testMessageA = testMessageKind(0)
	testMessageB = testMessageKind(1)
)

type testMessage struct {
	foo int32
}

type errorMessage struct{}

var errTest = fmt.Errorf("error")

type testSubscriber struct {
	msgs     []int32
	enabled  bool
	fail     bool
	noResult bool
}

// Implements api.MessageSubscriber.
func (s *testSubscriber) ExecuteMessage(_ *api.Context, _, msg interface{}) (interface{}, error) {
	switch m := msg.(type) {
	case *testMessage:
		s.msgs = append(s.msgs, m.foo)
		if s.fail {
			return nil, errTest
		}
		if s.noResult {
			return nil, nil
		}
		return m.foo, nil
	case *errorMessage:
		return nil, errTest
	default:
		panic("unexpected message was delivered")
	}
}

// Implements api.TogglableMessageSubscriber.
func (s *testSubscriber) Enabled(_ *api.Context) (bool, error) {
	return s.enabled, nil
}

func TestMessageDispatcher(t *testing.T) {
	require := require.New(t)

	appState := api.NewMockApplicationState(&api.MockApplicationStateConfig{})
	ctx := appState.NewContext(api.ContextBeginBlock)
	defer ctx.Close()

	var md messageDispatcher

	// Publish without subscribers should work.
	res, err := md.Publish(ctx, testMessageA, &testMessage{foo: 42})
	require.Error(err, "Publish")
	require.Equal(api.ErrNoSubscribers, err)
	require.Nil(res, "Publish results should be empty")

	// With a disabled subscriber should behave same as with no subscribers.
	var ms testSubscriber
	md.Subscribe(testMessageA, &ms)
	res, err = md.Publish(ctx, testMessageA, &testMessage{foo: 42})
	require.Error(err, "Publish")
	require.Equal(api.ErrNoSubscribers, err)
	require.Nil(res, "Publish results should be empty")
	require.Empty(ms.msgs, "no messages should be delivered when subscriber is disabled")

	// With an enabled subscriber.
	ms.enabled = true
	res, err = md.Publish(ctx, testMessageA, &testMessage{foo: 42})
	require.NoError(err, "Publish")
	require.EqualValues(int32(42), res, "correct publish message result")
	require.EqualValues([]int32{42}, ms.msgs, "correct messages should be delivered")

	res, err = md.Publish(ctx, testMessageA, &testMessage{foo: 43})
	require.NoError(err, "Publish")
	require.EqualValues(int32(43), res, "correct publish message result")
	require.EqualValues([]int32{42, 43}, ms.msgs, "correct messages should be delivered")

	res, err = md.Publish(ctx, testMessageB, &testMessage{foo: 44})
	require.Error(err, "Publish")
	require.Equal(api.ErrNoSubscribers, err)
	require.Nil(res, "publish message results should be empty")
	require.EqualValues([]int32{42, 43}, ms.msgs, "correct messages should be delivered")

	// Returning an error.
	res, err = md.Publish(ctx, testMessageA, &errorMessage{})
	require.Error(err, "Publish")
	require.Nil(nil, res, "publish message results should be empty")
	require.True(errors.Is(err, errTest), "returned error should be the correct one")

	// Multiple subscribers. Multiple subscribers returning results on the same message is an invariant violation.
	ms2 := testSubscriber{
		enabled:  true,
		noResult: true,
	}
	md.Subscribe(testMessageA, &ms2)
	res, err = md.Publish(ctx, testMessageA, &testMessage{foo: 44})
	require.NoError(err, "Publish")
	require.EqualValues(int32(44), res, "correct publish message result")
	require.EqualValues([]int32{42, 43, 44}, ms.msgs, "correct messages should be delivered")
	require.EqualValues([]int32{44}, ms2.msgs, "correct messages should be delivered")

	// Multiple subscribers returning results.
	ms2.noResult = false
	require.Panics(func() {
		_, _ = md.Publish(ctx, testMessageA, &testMessage{foo: 44})
	}, "multiple subscribers returning results should panic")
}
