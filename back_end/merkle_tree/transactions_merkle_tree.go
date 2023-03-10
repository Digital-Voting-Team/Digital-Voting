package merkle_tree

import (
	"digital-voting/transaction"
	"log"
)

type TransactionContent struct {
	tx transaction.ITransaction
}

func (t TransactionContent) CalculateHash() ([]byte, error) {
	return []byte(t.tx.HashString()), nil
}

func (t TransactionContent) Equals(other Content) (bool, error) {
	return t.tx.HashString() == other.(TransactionContent).tx.HashString(), nil
}

func getMerkleTree(transactions []transaction.ITransaction) *MerkleTree {
	var list []Content
	for _, tx := range transactions {
		list = append(list, TransactionContent{tx: tx})
	}

	resultTree, err := NewTree(list)
	if err != nil {
		log.Fatal(err)
	}

	return resultTree
}

func GetMerkleRoot(transactions []transaction.ITransaction) [32]byte {
	resultTree := getMerkleTree(transactions)

	root := [32]byte{}
	copy(root[:], resultTree.MerkleRoot())

	return root
}

func VerifyContent(transaction transaction.ITransaction, transactionList []transaction.ITransaction) bool {
	resultTree := getMerkleTree(transactionList)

	result, err := resultTree.VerifyContent(TransactionContent{tx: transaction})
	if err != nil {
		log.Fatal(err)
	}

	return result
}
