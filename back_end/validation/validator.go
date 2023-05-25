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
	MemPool           *MemPool
	Node              *node.Node
	BlockSigner       *signer.BlockSigner
	TransactionSigner *signer.TransactionSigner
	Blockchain        *blockchain.Blockchain

	NetworkToValidator   <-chan *block.Block
	ValidatorToNetwork   chan<- *block.Block
	BlockApprovalChannel <-chan *block.Block
	BlockDenialChannel   <-chan *block.Block
	TransactionChannel   <-chan tx.ITransaction

	TxResponseChannel    chan<- bool
	BlockResponseChannel chan<- ResponseMessage

	ValidatorKeysChannel <-chan []keys.PublicKeyBytes
}

func NewValidator(
	bc *blockchain.Blockchain,
	netToValChan <-chan *block.Block,
	valToNetChan chan<- *block.Block,
	blockApprovalChan <-chan *block.Block,
	blockDenialChan <-chan *block.Block,
	transactionChan <-chan tx.ITransaction,
	txResponseChan chan<- bool,
	blockResponseChan chan<- ResponseMessage,
	validatorKeysChan <-chan []keys.PublicKeyBytes,
) *Validator {
	validatorKeys, err := keys.Random(curve.NewCurve25519())
	if err != nil {
		log.Fatal(err)
	}
	v := &Validator{
		KeyPair:              validatorKeys,
		MemPool:              NewMemPool(),
		Node:                 node.NewNode(),
		BlockSigner:          signer.NewBlockSigner(),
		TransactionSigner:    signer.NewTransactionSigner(),
		Blockchain:           bc,
		NetworkToValidator:   netToValChan,
		ValidatorToNetwork:   valToNetChan,
		BlockApprovalChannel: blockApprovalChan,
		BlockDenialChannel:   blockDenialChan,
		TransactionChannel:   transactionChan,
		BlockResponseChannel: blockResponseChan,
		TxResponseChannel:    txResponseChan,
		ValidatorKeysChannel: validatorKeysChan,
	}

	v.StartRoutines()

	return v
}

func (v *Validator) StartRoutines() {
	go v.ValidateBlocks()
	go v.CreateAndSendBlock()
	go v.ApproveBlock()
	go v.DenyBlock()
	go v.UpdateValidatorKeys()
	go v.AddNewTransaction()
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
		v.BlockResponseChannel <- response
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
		v.MemPool.RestoreMemPool(deniedBlock.Body.Transactions, v.Node)
	}
}

// TODO: get last block hash from blockchain
func (v *Validator) CreateAndSendBlock() {
	ticker := time.NewTicker(time.Hour * 1)
	for {
		select {
		case <-ticker.C:
			hash := v.Blockchain.GetLastBlockHash()
			if v.MemPool.GetTransactionsCount() > 0 {
				v.ValidatorToNetwork <- v.CreateBlock(hash)
			}
		default:
			hash := v.Blockchain.GetLastBlockHash()
			if v.MemPool.GetTransactionsCount() >= MaxTransactionsInBlock {
				v.ValidatorToNetwork <- v.CreateBlock(hash)
			}
		}
	}
}

func (v *Validator) AddToMemPool(newTransaction tx.ITransaction) bool {
	v.Node.Mutex.Lock()
	response := newTransaction.CheckOnCreate(v.Node)
	v.Node.Mutex.Unlock()
	if response {
		response = v.MemPool.AddToMemPool(newTransaction)
	}
	return response
}

func (v *Validator) CreateBlock(previousBlockHash [32]byte) *block.Block {
	// Validator does not validate its block since it validated all transactions while adding them to MemPool

	// Takes up to MAX_TRANSACTIONS_IN_BLOCK transactions from beginning of MemPool and create block body with them
	maxNumber := MaxTransactionsInBlock
	blockBody := block.Body{
		Transactions: v.MemPool.GetWithUpperBound(maxNumber),
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
	v.SignAndUpdateBlock(newBlock)

	return newBlock
}

func (v *Validator) SignAndUpdateBlock(block *block.Block) {
	v.BlockSigner.SignAndUpdateBlock(v.KeyPair, block)
}

func (v *Validator) SignBlock(block *block.Block) (keys.PublicKeyBytes, singleSignature.SingleSignatureBytes) {
	return v.BlockSigner.SignBlock(v.KeyPair, block)
}

func (v *Validator) VerifyBlock(block *block.Block) bool {
	prevHashValid := block.Header.Previous == v.Blockchain.GetLastBlockHash()
	v.Node.Mutex.Lock()
	defer v.Node.Mutex.Unlock()
	return prevHashValid && block.Verify(v.Node)
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

func (v *Validator) AddNewTransaction() {
	for {
		newTransaction := <-v.TransactionChannel
		v.TxResponseChannel <- v.AddToMemPool(newTransaction)
	}
}
