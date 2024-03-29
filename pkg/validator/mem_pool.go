package validator

import (
	tx "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction"
	"math"
	"sync"
)

type MemPool struct {
	mutex        sync.Mutex
	Transactions []tx.ITransaction
}

func NewMemPool() *MemPool {
	return &MemPool{
		Transactions: []tx.ITransaction{},
	}
}

func (mp *MemPool) GetTransactionsCount() int {
	mp.mutex.Lock()
	defer mp.mutex.Unlock()
	return len(mp.Transactions)
}

func (mp *MemPool) IsInMemPool(transaction tx.ITransaction) bool {
	for _, v := range mp.Transactions {
		if v == transaction {
			return true
		}
	}
	return false
}

func (mp *MemPool) AddToMemPool(newTransaction tx.ITransaction) bool {
	mp.mutex.Lock()
	defer mp.mutex.Unlock()
	if !mp.IsInMemPool(newTransaction) {
		mp.Transactions = append(mp.Transactions, newTransaction)
		return true
	}
	return false
}

func (mp *MemPool) RestoreMemPool(transactions []tx.ITransaction) {
	mp.mutex.Lock()
	defer mp.mutex.Unlock()
	for _, transaction := range transactions {
		if !mp.IsInMemPool(transaction) {
			mp.Transactions = append([]tx.ITransaction{transaction}, mp.Transactions...)
		}
	}
}

func (mp *MemPool) GetWithUpperBound(upperBound int) []tx.ITransaction {
	mp.mutex.Lock()
	defer mp.mutex.Unlock()
	numberInBlock := int(math.Min(float64(len(mp.Transactions)), float64(upperBound)))
	transactionsToReturn := mp.Transactions[:numberInBlock]
	mp.Transactions = mp.Transactions[numberInBlock:]
	return transactionsToReturn
}
