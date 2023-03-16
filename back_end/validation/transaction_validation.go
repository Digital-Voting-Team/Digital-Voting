package validation

import (
	"digital-voting/identity_provider"
	"digital-voting/transaction"
)

func ValidateTransaction(tx transaction.ITransaction, identityProvider *identity_provider.IdentityProvider) bool {
	// TODO: think of how to actually get data from Identity Provider
	return tx.Validate(identityProvider)
}
