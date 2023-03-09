package block

import "digital-voting/transaction"

type Body struct {
	Transactions []transaction.ITransaction `json:"transaction"`
}

func (b *Body) AddTransaction(transaction transaction.ITransaction) {
	b.Transactions = append(b.Transactions, transaction)
}
