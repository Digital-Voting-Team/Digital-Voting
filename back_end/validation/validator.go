package validation

import (
	"digital-voting/account_manager"
	"digital-voting/block"
	"digital-voting/merkle_tree"
	"digital-voting/node"
	"digital-voting/signature/keys"
	"digital-voting/signer"
	tx "digital-voting/transaction"
	"math"
	"time"
)

type Validator struct {
	KeyPair              *keys.KeyPair
	ValidatorsPublicKeys map[keys.PublicKeyBytes]struct{}
	// TODO: think of data structure to store in future
	ValidatorsAddresses []any
	MemPool             []tx.ITransaction
	Node                *node.Node
	BlockSigner         *signer.BlockSigner
}

func (v *Validator) isInMemPool(transaction tx.ITransaction) bool {
	for _, v := range v.MemPool {
		if v == transaction {
			return true
		}
	}

	return false
}

func (v *Validator) AddToMemPool(newTransaction tx.ITransaction) {
	if !v.isInMemPool(newTransaction) && newTransaction.Validate(v.Node.AccountManager) {
		v.MemPool = append(v.MemPool, newTransaction)
	}
}

func (v *Validator) CreateBlock(previousBlockHash [32]byte) *block.Block {
	// Validator does not validate its block since it validated all transactions while adding them to MemPool

	// Takes up to 20 transactions from beginning of MemPool and create block body with them
	maxNumber := 20
	numberInBlock := int(math.Min(float64(len(v.MemPool)), float64(maxNumber)))
	blockBody := block.Body{
		Transactions: v.MemPool[:numberInBlock],
	}

	// Create block header
	blockHeader := block.Header{
		Previous:   previousBlockHash,
		TimeStamp:  uint64(time.Now().Unix()),
		MerkleRoot: merkle_tree.GetMerkleRoot(blockBody.Transactions),
	}

	// Create block itself
	newBlock := &block.Block{
		Header: blockHeader,
		Body:   blockBody,
	}

	// Sign block
	v.SignBlock(newBlock)

	// TODO: think of way to restore transactions in case of rejecting block
	v.MemPool = v.MemPool[numberInBlock:]

	return newBlock
}

func (v *Validator) SignBlock(block *block.Block) {
	v.BlockSigner.SignBlock(v.KeyPair, block)
}

func (v *Validator) AddBlockToChain(block *block.Block) {
	v.Node.Blockchain.AddBlock(block)
}

type IdentityActualizer interface {
	ActualizeIdentities(accountManager *account_manager.AccountManager)
}

func (v *Validator) ActualizeIdentityProvider(block *block.Block) {
	for _, transaction := range block.Body.Transactions {
		txExact, ok := transaction.GetTxBody().(IdentityActualizer)
		if ok {
			txExact.ActualizeIdentities(v.Node.AccountManager)
		}
	}
}
