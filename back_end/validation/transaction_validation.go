package validation

import (
	"digital-voting/node"
	"digital-voting/transaction"
)

func CheckOnCreateTransaction(tx transaction.ITransaction, node *node.Node) bool {
	// TODO: think of how to actually get data from Identity Provider
	return tx.CheckOnCreate(node)
}
