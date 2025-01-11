// Package token implements the token-related parts of the staking API.
package token

import "github.com/oasisprotocol/oasis-core/go/common/errors"

const (
	// ModuleName is a unique module name for the staking/token module.
	ModuleName = "staking/token"

	// TokenSymbolMaxLength is the maximum length of the token symbol.
	TokenSymbolMaxLength = 8
	// TokenSymbolRegexp is the regular expression defining valid token symbol characters.
	TokenSymbolRegexp = "^[A-Z]+$" // nolint: gosec // Not that kind of token :).
	// TokenValueExponentMaxValue is the maximum value of token's value base-10 exponent.
	TokenValueExponentMaxValue = 20
)

// ErrInvalidTokenValueExponent is the error returned when an invalid token's
// value base-10 exponent is specified.
var ErrInvalidTokenValueExponent = errors.New(ModuleName, 1, "staking/token: invalid token's value exponent")
