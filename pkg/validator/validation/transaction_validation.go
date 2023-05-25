package validation

import (
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository"
)

func CheckOnCreateTransaction(tx transaction.ITransaction, indexedData *repository.IndexedData) bool {
	// TODO: think of how to actually get data from Identity Provider
	return tx.CheckOnCreate(indexedData)
}
