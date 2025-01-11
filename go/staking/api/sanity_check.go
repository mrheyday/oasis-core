// Package api implements the staking backend API.
package api

import (
	"fmt"
	"regexp"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/staking/api/token"
)

// SanityCheck performs a sanity check on the consensus parameters.
func (p *ConsensusParameters) SanityCheck() error {
	if !flags.DebugDontBlameOasis() {
		if p.DebugBypassStake {
			return fmt.Errorf("one or more unsafe debug flags set")
		}
	}

	// Thresholds.
	for _, kind := range ThresholdKinds {
		val, ok := p.Thresholds[kind]
		if !ok {
			return fmt.Errorf("threshold for kind '%s' not defined", kind)
		}
		if !val.IsValid() {
			return fmt.Errorf("threshold '%s' has invalid value", kind)
		}
	}

	// Fee splits.
	if !p.FeeSplitWeightPropose.IsValid() {
		return fmt.Errorf("fee split weight propose has invalid value")
	}
	if !p.FeeSplitWeightVote.IsValid() {
		return fmt.Errorf("fee split weight vote has invalid value")
	}
	if !p.FeeSplitWeightNextPropose.IsValid() {
		return fmt.Errorf("fee split weight next propose has invalid value")
	}
	if p.FeeSplitWeightPropose.IsZero() && p.FeeSplitWeightVote.IsZero() && p.FeeSplitWeightNextPropose.IsZero() {
		return fmt.Errorf("fee split proportions are all zero")
	}

	// MinCommissionRate bound.
	if p.CommissionScheduleRules.MinCommissionRate.Cmp(CommissionRateDenominator) > 0 {
		return fmt.Errorf("minimum commission %v/%v over unity", p.CommissionScheduleRules, CommissionRateDenominator)
	}

	// Reward schedule steps must be sequential.
	var prevUntil beacon.EpochTime
	for _, step := range p.RewardSchedule {
		if !step.Scale.IsValid() || step.Scale.Cmp(RewardAmountDenominator) == 1 {
			return fmt.Errorf("reward scale must be a non-negative integer smaller than %s", RewardAmountDenominator.String())
		}
		if step.Until == beacon.EpochInvalid {
			return fmt.Errorf("reward until field must be a valid epoch")
		}
		if step.Until <= prevUntil {
			return fmt.Errorf("reward schedule steps must be sequential (previous is %d, current is %d)", prevUntil, step.Until)
		}
		prevUntil = step.Until
	}

	return nil
}

// SanityCheck performs a sanity check on the consensus parameter changes.
func (c *ConsensusParameterChanges) SanityCheck() error {
	if c.DebondingInterval == nil &&
		c.RewardSchedule == nil &&
		c.GasCosts == nil &&
		c.MinDelegationAmount == nil &&
		c.MinTransferAmount == nil &&
		c.MinTransactBalance == nil &&
		c.MinCommissionRate == nil &&
		c.DisableTransfers == nil &&
		c.DisableDelegation == nil &&
		c.AllowEscrowMessages == nil &&
		c.MaxAllowances == nil &&
		c.FeeSplitWeightPropose == nil &&
		c.FeeSplitWeightVote == nil &&
		c.FeeSplitWeightNextPropose == nil &&
		c.RewardFactorEpochSigned == nil &&
		c.RewardFactorBlockProposed == nil {
		return fmt.Errorf("consensus parameter changes should not be empty")
	}
	return nil
}

// SanityCheckAccount examines an account's balances.
// Adds the balances to a running total `total`.
func SanityCheckAccount(
	total *quantity.Quantity,
	parameters *ConsensusParameters,
	now beacon.EpochTime,
	addr Address,
	acct *Account,
	totalSupply *quantity.Quantity,
) error {
	if !addr.IsValid() {
		return fmt.Errorf("staking: sanity check failed: account has invalid address: %s", addr)
	}
	if !acct.General.Balance.IsValid() {
		return fmt.Errorf(
			"staking: sanity check failed: general balance is invalid for account %s", addr,
		)
	}
	if !acct.Escrow.Active.Balance.IsValid() {
		return fmt.Errorf(
			"staking: sanity check failed: escrow active balance is invalid for account %s", addr,
		)
	}
	if !acct.Escrow.Debonding.Balance.IsValid() {
		return fmt.Errorf(
			"staking: sanity check failed: escrow debonding balance is invalid for account %s",
			addr,
		)
	}

	_ = total.Add(&acct.General.Balance)
	_ = total.Add(&acct.Escrow.Active.Balance)
	_ = total.Add(&acct.Escrow.Debonding.Balance)

	commissionScheduleShallowCopy := acct.Escrow.CommissionSchedule
	if err := commissionScheduleShallowCopy.PruneAndValidate(&parameters.CommissionScheduleRules, now); err != nil {
		return fmt.Errorf(
			"staking: sanity check failed: commission schedule for account %s is invalid: %+v",
			addr, err,
		)
	}

	for beneficiary, allowance := range acct.General.Allowances {
		if !beneficiary.IsValid() {
			return fmt.Errorf("staking: sanity check failed: account %s allowance has invalid beneficiary address %s", addr, beneficiary)
		}
		if !allowance.IsValid() {
			return fmt.Errorf("staking: sanity check failed: account %s allowance is invalid for beneficiary %s", addr, beneficiary)
		}
		if allowance.Cmp(totalSupply) > 0 {
			return fmt.Errorf("staking: sanity check failed: account %s allowance is greater than total supply for beneficiary %s", addr, beneficiary)
		}
	}

	return nil
}

// SanityCheckDelegations examines an account's delegations.
func SanityCheckDelegations(addr Address, account *Account, delegations map[Address]*Delegation) error {
	if !addr.IsValid() {
		return fmt.Errorf("staking: sanity check failed: delegation to %s: address is invalid", addr)
	}
	var shares quantity.Quantity
	var numDelegations uint64
	for delegatorAddr, delegation := range delegations {
		if !delegatorAddr.IsValid() {
			return fmt.Errorf(
				"staking: sanity check failed: delegation from %s to %s: delegator address is invalid",
				delegatorAddr, addr,
			)
		}
		_ = shares.Add(&delegation.Shares) //nolint:gosec
		numDelegations++
	}

	sharesExpected := account.Escrow.Active.TotalShares

	if shares.Cmp(&sharesExpected) != 0 {
		return fmt.Errorf(
			"staking: sanity check failed: all shares of all delegations (%s) for account %s don't add up to account's total active shares in escrow (%s)",
			shares, addr, sharesExpected,
		)
	}

	// Account's Escrow.Active.Balance must be 0 if account has no delegations.
	if numDelegations == 0 {
		if !account.Escrow.Active.Balance.IsZero() {
			return fmt.Errorf(
				"staking: sanity check failed: account %s has no delegations, but non-zero active escrow balance",
				addr,
			)
		}
	}

	return nil
}

// SanityCheckDebondingDelegations examines an account's debonding delegations.
func SanityCheckDebondingDelegations(addr Address, account *Account, delegations map[Address][]*DebondingDelegation) error {
	if !addr.IsValid() {
		return fmt.Errorf("staking: sanity check failed: debonding delegation to %s: address is invalid", addr)
	}
	var shares quantity.Quantity
	var numDebondingDelegations uint64
	for delegatorAddr, dels := range delegations {
		if !delegatorAddr.IsValid() {
			return fmt.Errorf(
				"staking: sanity check failed: debonding delegation from %s to %s: delegator address is invalid",
				delegatorAddr, addr,
			)
		}
		for _, delegation := range dels {
			_ = shares.Add(&delegation.Shares) //nolint:gosec
			numDebondingDelegations++
		}
	}

	sharesExpected := account.Escrow.Debonding.TotalShares

	if shares.Cmp(&sharesExpected) != 0 {
		return fmt.Errorf(
			"staking: sanity check failed: all shares of all debonding delegations (%s) for account %s don't add up to account's total debonding shares in escrow (%s)",
			shares, addr, sharesExpected,
		)
	}

	// Account's Escrow.Debonding.Balance must be 0 if account has no debonding delegations.
	if numDebondingDelegations == 0 {
		if !account.Escrow.Debonding.Balance.IsZero() {
			return fmt.Errorf(
				"staking: sanity check failed: account %s has no debonding delegations, but non-zero debonding escrow balance",
				addr,
			)
		}
	}
	return nil
}

// SanityCheckAccountShares examines an account's share pools.
func SanityCheckAccountShares(
	addr Address,
	acct *Account,
	delegations map[Address]*Delegation,
	debondingDelegations map[Address][]*DebondingDelegation,
) error {
	// Count the delegations for this account and add up the total shares.
	var shares quantity.Quantity
	var numDelegations uint64
	for _, d := range delegations {
		_ = shares.Add(&d.Shares) //nolint:gosec
		numDelegations++
	}
	// Account's total active shares in escrow should match delegations.
	if shares.Cmp(&acct.Escrow.Active.TotalShares) != 0 {
		return fmt.Errorf(
			"staking: sanity check failed: delegations (%s) for account %s don't match account's total active shares in escrow (%s)",
			shares, addr, acct.Escrow.Active.TotalShares,
		)
	}
	// If there are no delegations, the active escrow balance should be 0.
	if numDelegations == 0 {
		if !acct.Escrow.Active.Balance.IsZero() {
			return fmt.Errorf(
				"staking: sanity check failed: account %s has no delegations, but non-zero active escrow balance",
				addr,
			)
		}
	}

	// Count the debonding delegations for this account and add up the total shares.
	var debondingShares quantity.Quantity
	var numDebondingDelegations uint64
	for _, dels := range debondingDelegations {
		for _, d := range dels {
			_ = debondingShares.Add(&d.Shares) //nolint:gosec
			numDebondingDelegations++
		}
	}
	// Account's total debonding shares in escrow should match debonding delegations.
	if debondingShares.Cmp(&acct.Escrow.Debonding.TotalShares) != 0 {
		return fmt.Errorf(
			"staking: sanity check failed: debonding delegations (%s) for account %s don't match account's total debonding shares in escrow (%s)",
			debondingShares, addr, acct.Escrow.Debonding.TotalShares,
		)
	}
	// If there are no debonding delegations, the debonding escrow balance should be 0.
	if numDebondingDelegations == 0 {
		if !acct.Escrow.Debonding.Balance.IsZero() {
			return fmt.Errorf(
				"staking: sanity check failed: account %s has no debonding delegations, but non-zero debonding escrow balance",
				addr,
			)
		}
	}
	return nil
}

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck(now beacon.EpochTime) error { // nolint: gocyclo
	if err := g.Parameters.SanityCheck(); err != nil {
		return fmt.Errorf("staking: sanity check failed: %w", err)
	}

	tokenSymbolLength := len(g.TokenSymbol)
	if tokenSymbolLength == 0 {
		return fmt.Errorf("staking: sanity check failed: token symbol is empty")
	}
	if tokenSymbolLength > token.TokenSymbolMaxLength {
		return fmt.Errorf("staking: sanity check failed: token symbol exceeds maximum length")
	}
	match := regexp.MustCompile(token.TokenSymbolRegexp).FindString(g.TokenSymbol)
	if match == "" {
		return fmt.Errorf("staking: sanity check failed: token symbol should match '%s'", token.TokenSymbolRegexp)
	}

	if g.TokenValueExponent > token.TokenValueExponentMaxValue {
		return fmt.Errorf("staking: sanity check failed: token value exponent is invalid")
	}

	if !g.TotalSupply.IsValid() {
		return fmt.Errorf("staking: sanity check failed: total supply is invalid")
	}

	if !g.CommonPool.IsValid() {
		return fmt.Errorf("staking: sanity check failed: common pool is invalid")
	}

	if !g.LastBlockFees.IsValid() {
		return fmt.Errorf("staking: sanity check failed: last block fees is invalid")
	}

	// Check if the total supply adds up:
	// common pool + last block fees + all balances in the ledger.
	// Check all commission schedules.
	var total quantity.Quantity
	for addr, acct := range g.Ledger {
		err := SanityCheckAccount(&total, &g.Parameters, now, addr, acct, &g.TotalSupply)
		if err != nil {
			return err
		}

		// Make sure that the stake accumulator is empty as otherwise it could be inconsistent with
		// what is registered in the genesis block.
		if len(acct.Escrow.StakeAccumulator.Claims) > 0 {
			return fmt.Errorf("staking: non-empty stake accumulator in genesis")
		}
	}
	_ = total.Add(&g.GovernanceDeposits)
	_ = total.Add(&g.CommonPool)
	_ = total.Add(&g.LastBlockFees)
	if total.Cmp(&g.TotalSupply) != 0 {
		return fmt.Errorf(
			"staking: sanity check failed: balances in accounts, plus governance deposits, plus common pool, plus last block fees (%s), does not add up to total supply (%s)",
			total.String(), g.TotalSupply.String(),
		)
	}

	// All shares of all delegations for a given account must add up to account's Escrow.Active.TotalShares.
	for addr, delegations := range g.Delegations {
		acct := g.Ledger[addr]
		if acct == nil {
			return fmt.Errorf(
				"staking: sanity check failed: delegation specified for a nonexisting account: %v",
				addr,
			)
		}
		if err := SanityCheckDelegations(addr, acct, delegations); err != nil {
			return err
		}
	}

	// All shares of all debonding delegations for a given account must add up to account's Escrow.Debonding.TotalShares.
	for addr, delegations := range g.DebondingDelegations {
		acct := g.Ledger[addr]
		if acct == nil {
			return fmt.Errorf(
				"staking: sanity check failed: debonding delegation specified for a nonexisting account: %v", addr,
			)
		}
		if err := SanityCheckDebondingDelegations(addr, acct, delegations); err != nil {
			return err
		}
	}

	// The burn address is actually "unused" for reasonable definitions of "unused".
	if ba := g.Ledger[BurnAddress]; ba != nil {
		if !ba.General.Balance.IsZero() {
			return fmt.Errorf(
				"staking: sanity check failed: burn address has non-zero balance: %v", ba.General.Balance,
			)
		}
		if ba.General.Nonce != 0 {
			return fmt.Errorf(
				"staking: sanity check failed: burn address has non-zero nonce: %v", ba.General.Nonce,
			)
		}
		if len(ba.General.Allowances) != 0 {
			return fmt.Errorf(
				"staking: sanity check failed: burn address has non-empty allowances",
			)
		}
	}

	// Check the above two invariants for each account as well.
	for addr, acct := range g.Ledger {
		if err := SanityCheckAccountShares(addr, acct, g.Delegations[addr], g.DebondingDelegations[addr]); err != nil {
			return err
		}
	}

	return nil
}

// SanityCheckStake compares generated escrow accounts with actual ones.
func SanityCheckStake(
	accounts map[Address]*Account,
	escrows map[Address]*EscrowAccount,
	thresholds map[ThresholdKind]quantity.Quantity,
	isGenesis bool,
) error {
	// For a Genesis document, check if accounts have enough stake for all its stake claims.
	// NOTE: We can't perform this check at an arbitrary point since the entity could
	// reclaim its stake from the escrow but its nodes and/or runtimes will only be
	// ineligible/suspended at the next epoch transition.
	if isGenesis {
		// Populate escrow accounts with the same active balance and shares number.
		for addr, escrow := range escrows {
			acct, ok := accounts[addr]
			if !ok {
				continue
			}

			escrow.Active.Balance = acct.Escrow.Active.Balance
			escrow.Active.TotalShares = acct.Escrow.Active.TotalShares
		}

		for addr, escrow := range escrows {
			if err := escrow.CheckStakeClaims(thresholds); err != nil {
				expected := "unknown"
				expectedQty, err2 := escrow.StakeAccumulator.TotalClaims(thresholds, nil)
				if err2 == nil {
					expected = expectedQty.String()
				}
				return fmt.Errorf("insufficient stake for account %s (expected: %s got: %s): %w",
					addr,
					expected,
					escrow.Active.Balance,
					err,
				)
			}
		}

		return nil
	}

	// Otherwise, compare the expected accumulator state with the actual one.
	// NOTE: We can't perform this check for the Genesis document since it is not allowed to
	// have non-empty stake accumulators.
	seen := make(map[Address]struct{})
	for addr, escrow := range escrows {
		seen[addr] = struct{}{}

		var actualEscrow EscrowAccount
		acct, ok := accounts[addr]
		if ok {
			actualEscrow = acct.Escrow
		}

		expectedClaims := escrow.StakeAccumulator.Claims
		actualClaims := actualEscrow.StakeAccumulator.Claims
		if len(expectedClaims) != len(actualClaims) {
			return fmt.Errorf("incorrect number of stake claims for account %s (expected: %d got: %d)",
				addr,
				len(expectedClaims),
				len(actualClaims),
			)
		}
		for claim, expectedThresholds := range expectedClaims {
			thresholds, ok := actualClaims[claim]
			if !ok {
				return fmt.Errorf("missing claim %s for account %s", claim, addr)
			}
			if len(thresholds) != len(expectedThresholds) {
				return fmt.Errorf("incorrect number of thresholds for claim %s for account %s (expected: %d got: %d)",
					claim,
					addr,
					len(expectedThresholds),
					len(thresholds),
				)
			}
			for i, expectedThreshold := range expectedThresholds {
				threshold := thresholds[i]
				if !threshold.Equal(&expectedThreshold) { // nolint: gosec
					return fmt.Errorf("incorrect threshold in position %d for claim %s for account %s (expected: %s got: %s)",
						i,
						claim,
						addr,
						expectedThreshold,
						threshold,
					)
				}
			}
		}
	}

	for addr, acct := range accounts {
		if _, ok := seen[addr]; ok {
			continue
		}

		actualClaims := acct.Escrow.StakeAccumulator.Claims
		if len(actualClaims) != 0 {
			return fmt.Errorf("incorrect number of stake claims for account %s (expected: 0 got: %d)",
				addr,
				len(actualClaims),
			)
		}
	}

	return nil
}
