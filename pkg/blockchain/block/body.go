package block

import (
	tx "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction"
)

type Body struct {
	Transactions []tx.ITransaction `json:"transactions"`
}

func (b *Body) AddTransaction(transaction tx.ITransaction) {
	b.Transactions = append(b.Transactions, transaction)
}
