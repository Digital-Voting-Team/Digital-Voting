package validation

import (
	"digital-voting/block"
	"digital-voting/blockchain"
	"digital-voting/merkle_tree"
	"digital-voting/node"
	"digital-voting/node/account_manager"
	"digital-voting/signature/curve"
	"digital-voting/signature/keys"
	singleSignature "digital-voting/signature/signatures/single_signature"
	"digital-voting/signer"
	tx "digital-voting/transaction"
	"log"
	"math"
	"time"
)

const MaxTransactionsInBlock = 5

type ResponseMessage struct {
	VerificationSuccess bool                                 `json:"verification_success"`
	PublicKey           keys.PublicKeyBytes                  `json:"public_key"`
	Signature           singleSignature.SingleSignatureBytes `json:"signature"`
}

type Validator struct {
	KeyPair           *keys.KeyPair
	MemPool           []tx.ITransaction
	Node              *node.Node
	BlockSigner       *signer.BlockSigner
	TransactionSigner *signer.TransactionSigner
	Blockchain        *blockchain.Blockchain

	NetworkToValidator   <-chan *block.Block
	ValidatorToNetwork   chan<- *block.Block
	BlockApprovalChannel <-chan *block.Block
	BlockDenialChannel   <-chan *block.Block
	TransactionChannel   chan tx.ITransaction
	ResponseChannel      chan<- ResponseMessage
	ValidatorKeysChannel <-chan []keys.PublicKeyBytes
}

func NewValidator(
	bc *blockchain.Blockchain,
	netToValChan <-chan *block.Block,
	valToNetChan chan<- *block.Block,
	blockApprovalChan <-chan *block.Block,
	blockDenialChan <-chan *block.Block,
	transactionChan chan tx.ITransaction,
	responseChan chan<- ResponseMessage,
	validatorKeysChan <-chan []keys.PublicKeyBytes,
) *Validator {
	validatorKeys, err := keys.Random(curve.NewCurve25519())
	if err != nil {
		log.Fatal(err)
	}
	v := &Validator{
		KeyPair:              validatorKeys,
		MemPool:              []tx.ITransaction{},
		Node:                 node.NewNode(),
		BlockSigner:          signer.NewBlockSigner(),
		TransactionSigner:    signer.NewTransactionSigner(),
		Blockchain:           bc,
		NetworkToValidator:   netToValChan,
		ValidatorToNetwork:   valToNetChan,
		BlockApprovalChannel: blockApprovalChan,
		BlockDenialChannel:   blockDenialChan,
		TransactionChannel:   transactionChan,
		ResponseChannel:      responseChan,
		ValidatorKeysChannel: validatorKeysChan,
	}

	v.StartRoutines()

	return v
}

func (v *Validator) StartRoutines() {
	go v.ValidateBlocks()
	go v.ValidateTransactions()
	go v.CreateAndSendBlock()
	go v.ApproveBlock()
	go v.DenyBlock()
	go v.UpdateValidatorKeys()
}

// ValidateBlocks wait for blocks from channel and validate them
func (v *Validator) ValidateBlocks() {
	var response ResponseMessage
	for {
		newBlock := <-v.NetworkToValidator
		if v.VerifyBlock(newBlock) {
			log.Printf("Successfully verified block %s", newBlock.GetHashString())
			publicKey, signature := v.SignBlock(newBlock)
			response = ResponseMessage{
				VerificationSuccess: true,
				PublicKey:           publicKey,
				Signature:           signature,
			}
		} else {
			response = ResponseMessage{
				VerificationSuccess: false,
			}
		}
		v.ResponseChannel <- response
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
		approvedBlock := <-v.BlockApprovalChannel
		if v.VerifyBlock(approvedBlock) {
			err := v.AddBlockToChain(approvedBlock)
			v.ActualizeNodeData(approvedBlock)
			if err != nil {
				log.Fatalln(err)
			}
			log.Printf("Successfully added block %s", approvedBlock.GetHashString())
		}
	}
}

// DenyBlock wait for transactions from channel, restore transactions from it
func (v *Validator) DenyBlock() {
	for {
		deniedBlock := <-v.BlockDenialChannel
		for _, transaction := range deniedBlock.Body.Transactions {
			if transaction.Verify(v.Node) {
				v.MemPool = append([]tx.ITransaction{transaction}, v.MemPool...)
			}
		}
	}
}

// TODO: get last block hash from blockchain
func (v *Validator) CreateAndSendBlock() {
	ticker := time.NewTicker(time.Hour * 1)
	for {
		select {
		case <-ticker.C:
			hash := v.Blockchain.GetLastBlockHash()
			if len(v.MemPool) > 0 {
				v.ValidatorToNetwork <- v.CreateBlock(hash)
			}
		default:
			hash := v.Blockchain.GetLastBlockHash()
			if len(v.MemPool) >= MaxTransactionsInBlock {
				v.ValidatorToNetwork <- v.CreateBlock(hash)
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

	// Takes up to MAX_TRANSACTIONS_IN_BLOCK transactions from beginning of MemPool and create block body with them
	maxNumber := MaxTransactionsInBlock
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
	v.Node.Mutex.Lock()
	defer v.Node.Mutex.Unlock()
	return block.Verify(v.Node, v.Blockchain.GetLastBlockHash())
}

func (v *Validator) AddBlockToChain(block *block.Block) error {
	return v.Blockchain.AddBlock(block)
}

type IndexedDataActualizer interface {
	ActualizeIndexedData(node *node.Node)
}

func (v *Validator) ActualizeNodeData(block *block.Block) {
	v.Node.Mutex.Lock()
	defer v.Node.Mutex.Unlock()
	for _, transaction := range block.Body.Transactions {
		txExact, ok := transaction.GetTxBody().(IndexedDataActualizer)
		if ok {
			txExact.ActualizeIndexedData(v.Node)
		}
	}
}

func (v *Validator) UpdateValidatorKeys() {
	for {
		newValidatorKeys := <-v.ValidatorKeysChannel
		v.Node.Mutex.Lock()
		v.Node.AccountManager.ValidatorPubKeys = map[keys.PublicKeyBytes]struct{}{}
		for _, key := range newValidatorKeys {
			v.Node.AccountManager.AddPubKey(key, account_manager.Validator)
		}
		v.Node.Mutex.Unlock()
	}
}
