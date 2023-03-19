package validation

import (
	"digital-voting/block"
	"digital-voting/identity_provider"
	"digital-voting/merkle_tree"
	"digital-voting/signature/keys"
	"digital-voting/signer"
	"digital-voting/transaction"
	"time"
)

type Validator struct {
	KeyPair              *keys.KeyPair
	ValidatorsPublicKeys map[[33]byte]struct{}
	// TODO: think of data structure to store in future
	ValidatorsAddresses []any
	MemPool             []transaction.ITransaction
	IdentityProvider    *identity_provider.IdentityProvider
}

func (v *Validator) isInMemPool(transaction transaction.ITransaction) bool {
	for _, v := range v.MemPool {
		if v == transaction {
			return true
		}
	}

	return false
}

func (v *Validator) AddToMemPool(newTransaction transaction.ITransaction) {
	if !v.isInMemPool(newTransaction) && newTransaction.Validate(v.IdentityProvider) {
		v.MemPool = append(v.MemPool, newTransaction)
	}
}

func (v *Validator) CreateBlock(previousBlockHash [32]byte) *block.Block {
	// Validator does not validate its block since it validated all transactions while adding them to MemPool

	// Takes up to 20 transactions from beginning of MemPool and create block body with them
	blockBody := block.Body{
		Transactions: v.MemPool[:20],
	}

	// Create block header
	blockHeader := block.Header{
		Previous:   previousBlockHash,
		TimeStamp:  uint64(time.Now().Unix()),
		MerkleRoot: merkle_tree.GetMerkleRoot(blockBody.Transactions),
	}

	// Sign block
	newBlock := &block.Block{
		Header: blockHeader,
		Body:   blockBody,
	}

	blockSigner := signer.NewBlockSigner()
	blockSigner.SignBlock(v.KeyPair, newBlock)

	return newBlock
}

type BlockChain interface {
	AddBlock(block *block.Block)
}

// AddBlockToChain TODO: add actual blockchain parameter after blockchain implementation
func (v *Validator) AddBlockToChain(blockChain BlockChain, block *block.Block) {
	blockChain.AddBlock(block)
}
