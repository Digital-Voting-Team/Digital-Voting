package validation

import (
	"digital-voting/block"
	"digital-voting/blockchain"
	"digital-voting/merkle_tree"
	"digital-voting/node"
	"digital-voting/signature/curve"
	"digital-voting/signature/keys"
	singleSignature "digital-voting/signature/signatures/single_signature"
	"digital-voting/signer"
	tx "digital-voting/transaction"
	"log"
	"math"
	"time"
)

type AcceptanceMessage struct {
	BlockHash [32]byte                             `json:"block_hash"`
	PublicKey keys.PublicKeyBytes                  `json:"public_key"`
	Signature singleSignature.SingleSignatureBytes `json:"signature"`
}

type Validator struct {
	KeyPair              *keys.KeyPair
	ValidatorsPublicKeys map[keys.PublicKeyBytes]struct{}
	// TODO: think of data structure to store in future
	ValidatorsAddresses  []any
	MemPool              []tx.ITransaction
	Node                 *node.Node
	BlockSigner          *signer.BlockSigner
	TransactionSigner    *signer.TransactionSigner
	BlockChannelIn       <-chan *block.Block
	BlockChannelOut      chan<- *block.Block
	BlockApprovalChannel <-chan *block.Block
	TransactionChannel   chan tx.ITransaction
	AcceptanceChannel    chan<- AcceptanceMessage
	Blockchain           *blockchain.Blockchain
}

func NewValidator(
	blockChanIn <-chan *block.Block,
	blockChanOut chan<- *block.Block,
	blockApprovalChan <-chan *block.Block,
	transactionChan chan tx.ITransaction,
	acceptanceChan chan<- AcceptanceMessage,
	bc *blockchain.Blockchain,
) *Validator {
	validatorKeys, err := keys.Random(curve.NewCurve25519())
	if err != nil {
		log.Fatal(err)
	}
	v := &Validator{
		KeyPair:              validatorKeys,
		ValidatorsPublicKeys: map[keys.PublicKeyBytes]struct{}{},
		MemPool:              []tx.ITransaction{},
		Node:                 node.NewNode(),
		BlockSigner:          signer.NewBlockSigner(),
		TransactionSigner:    signer.NewTransactionSigner(),
		BlockChannelIn:       blockChanIn,
		BlockApprovalChannel: blockApprovalChan,
		BlockChannelOut:      blockChanOut,
		TransactionChannel:   transactionChan,
		AcceptanceChannel:    acceptanceChan,
		Blockchain:           bc,
	}

	go v.ValidateBlocks()
	go v.ValidateTransactions()
	go v.CreateBlockTicker()
	go v.ApproveBlock()

	return v
}

// ValidateBlocks wait for blocks from channel and validate them
func (v *Validator) ValidateBlocks() {
	for {
		newBlock := <-v.BlockChannelIn
		if v.VerifyBlock(newBlock) {
			publicKey, signature := v.SignBlock(newBlock)
			v.AcceptanceChannel <- AcceptanceMessage{
				BlockHash: newBlock.GetHash(),
				PublicKey: publicKey,
				Signature: signature,
			}
		}
	}
}

// ValidateTransactions wait for transactions from channel and validate them
func (v *Validator) ValidateTransactions() {
	for {
		v.AddToMemPool(<-v.TransactionChannel)
	}
}

// ApproveBlock wait for transactions from channel, approve and add them to blockchain
func (v *Validator) ApproveBlock() {
	for {
		newBlock := <-v.BlockApprovalChannel
		if v.VerifyBlock(newBlock) {
			err := v.AddBlockToChain(newBlock)
			if err != nil {
				log.Fatalln(err)
			}
		}
	}
}

// TODO: get last block hash from blockchain
func (v *Validator) CreateBlockTicker() {
	ticker := time.NewTicker(time.Hour * 1)
	for {
		select {
		case <-ticker.C:
			hash := v.Blockchain.GetLastBlockHash()
			v.BlockChannelOut <- v.CreateBlock(hash)
		default:
			hash := v.Blockchain.GetLastBlockHash()
			if len(v.MemPool) >= 5 {
				v.BlockChannelOut <- v.CreateBlock(hash)
			}
		}
	}
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
	if !v.isInMemPool(newTransaction) && newTransaction.CheckOnCreate(v.Node) {
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

func (v *Validator) SignAndUpdateBlock(block *block.Block) {
	v.BlockSigner.SignAndUpdateBlock(v.KeyPair, block)
}

func (v *Validator) SignBlock(block *block.Block) (keys.PublicKeyBytes, singleSignature.SingleSignatureBytes) {
	return v.BlockSigner.SignBlock(v.KeyPair, block)
}

func (v *Validator) VerifyBlock(block *block.Block) bool {
	return block.Verify(v.Node)
}

func (v *Validator) AddBlockToChain(block *block.Block) error {
	return v.Blockchain.AddBlock(block)
}

type IdentityActualizer interface {
	ActualizeIdentities(node *node.Node)
}

func (v *Validator) ActualizeIdentityProvider(block *block.Block) {
	for _, transaction := range block.Body.Transactions {
		txExact, ok := transaction.GetTxBody().(IdentityActualizer)
		if ok {
			txExact.ActualizeIdentities(v.Node)
		}
	}
}
