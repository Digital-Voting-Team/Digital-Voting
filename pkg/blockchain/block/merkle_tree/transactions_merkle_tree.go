package merkle_tree

import (
	tx "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction"
	"log"
)

type TransactionContent struct {
	transaction tx.ITransaction
}

func (t TransactionContent) CalculateHash() ([]byte, error) {
	hash := t.transaction.GetHash()
	return hash[:], nil
}

func (t TransactionContent) Equals(other Content) (bool, error) {
	return t.transaction == other.(TransactionContent).transaction, nil
}

func getMerkleTree(transactions []tx.ITransaction) *MerkleTree {
	var list []Content
	for _, transaction := range transactions {
		list = append(list, TransactionContent{transaction: transaction})
	}

	resultTree, err := NewTree(list)
	if err != nil {
		log.Fatal(err)
	}

	return resultTree
}

func GetMerkleRoot(transactions []tx.ITransaction) [32]byte {
	resultTree := getMerkleTree(transactions)

	root := [32]byte{}
	copy(root[:], resultTree.MerkleRoot())

	return root
}

func VerifyContent(transaction tx.ITransaction, transactionList []tx.ITransaction) bool {
	resultTree := getMerkleTree(transactionList)

	result, err := resultTree.VerifyContent(TransactionContent{transaction: transaction})
	if err != nil {
		log.Fatal(err)
	}

	return result
}
