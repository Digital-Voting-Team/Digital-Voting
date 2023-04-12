package validation

import (
	"digital-voting/account_manager"
	"digital-voting/transaction"
)

func ValidateTransaction(tx transaction.ITransaction, accountManager *account_manager.AccountManager) bool {
	// TODO: think of how to actually get data from Identity Provider
	return tx.Validate(accountManager)
}
