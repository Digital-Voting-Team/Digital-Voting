package validation

import (
	"digital-voting/block"
	"digital-voting/identity_provider"
	"digital-voting/merkle_tree"
	"digital-voting/signature/keys"
	"digital-voting/signer"
	"digital-voting/transaction"
	"math"
	"time"
)

type Validator struct {
	KeyPair              *keys.KeyPair
	ValidatorsPublicKeys map[keys.PublicKeyBytes]struct{}
	// TODO: think of data structure to store in future
	ValidatorsAddresses []any
	MemPool             []transaction.ITransaction
	IdentityProvider    *identity_provider.IdentityProvider
	BlockSigner         *signer.BlockSigner
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

	return newBlock
}

func (v *Validator) SignBlock(block *block.Block) {
	v.BlockSigner.SignBlock(v.KeyPair, block)
}

type BlockChain interface {
	AddBlock(block *block.Block)
}

// AddBlockToChain TODO: add actual blockchain parameter after blockchain implementation
func (v *Validator) AddBlockToChain(blockChain BlockChain, block *block.Block) {
	blockChain.AddBlock(block)
}
