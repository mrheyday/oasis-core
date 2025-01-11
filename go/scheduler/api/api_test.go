package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

func TestSanityCheck(t *testing.T) {
	g := Genesis{}
	q1e19 := quantity.NewQuantity()
	require.NoError(t, q1e19.UnmarshalText([]byte("10_000_000_000_000_000_000")), "import 1e19")
	require.NoError(t, g.SanityCheck(q1e19, VotingPowerDistributionLinear), "sanity check total supply 1e19")
	q2e19 := quantity.NewQuantity()
	require.NoError(t, q2e19.UnmarshalText([]byte("20_000_000_000_000_000_000")), "import 2e19")
	require.Error(t, g.SanityCheck(q2e19, VotingPowerDistributionLinear), "sanity check total supply 2e19")
	q2e20 := quantity.NewQuantity()
	require.NoError(t, q2e20.UnmarshalText([]byte("200_000_000_000_000_000_000")), "import q2e20")
	require.Error(t, g.SanityCheck(q2e20, VotingPowerDistributionLinear), "sanity check total supply q2e20")
}

func TestVotingPowerDistribution(t *testing.T) {
	q1e19 := quantity.NewQuantity()
	require.NoError(t, q1e19.UnmarshalText([]byte("10_000_000_000_000_000_000")), "import 1e19")

	powerL, err := VotingPowerFromStake(q1e19, VotingPowerDistributionLinear)
	require.NoError(t, err, "VotingPowerFromStake should succeed for linear")

	powerS, err := VotingPowerFromStake(q1e19, VotingPowerDistributionSqrt)
	require.NoError(t, err, "VotingPowerFromStake should succeed for sqrt")

	require.True(t, powerL > 0, "linear should be greater than 0")
	require.True(t, powerS > 0, "sqrt should be greater than 0")
	require.True(t, powerL > powerS, "linear should be greater than sqrt")
}
