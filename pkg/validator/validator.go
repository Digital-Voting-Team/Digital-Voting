package validator

import (
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain"
	blk "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/block"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/block/merkle_tree"
	tx "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/curve"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
	ss "github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/signatures/single_signature"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signer"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository/account_manager"
	"log"
	"time"
)

var RegAdminPrivateKey = keys.PrivateKeyBytes{1}

const MaxTransactionsInBlock = 5

type ResponseMessage struct {
	VerificationSuccess bool                    `json:"verification_success"`
	PublicKey           keys.PublicKeyBytes     `json:"public_key"`
	Signature           ss.SingleSignatureBytes `json:"signature"`
}

type Validator struct {
	KeyPair     *keys.KeyPair
	MemPool     *MemPool
	Node        *repository.IndexedData
	BlockSigner *signer.BlockSigner
	Blockchain  *blockchain.Blockchain

	NetworkToValidator   <-chan *blk.Block
	ValidatorToNetwork   chan<- *blk.Block
	BlockApprovalChannel <-chan *blk.Block
	BlockDenialChannel   <-chan *blk.Block
	TransactionChannel   <-chan tx.ITransaction

	TxResponseChannel    chan<- bool
	BlockResponseChannel chan<- ResponseMessage

	ValidatorKeysChannel <-chan []keys.PublicKeyBytes
}

func NewValidator(
	bc *blockchain.Blockchain,
	netToValChan <-chan *blk.Block,
	valToNetChan chan<- *blk.Block,
	blockApprovalChan <-chan *blk.Block,
	blockDenialChan <-chan *blk.Block,
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
		Node:                 repository.NewIndexedData(),
		BlockSigner:          signer.NewBlockSigner(),
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
		v.RestoreMemPool(deniedBlock.Body.Transactions)
	}
}

func (v *Validator) RestoreMemPool(transactions []tx.ITransaction) {
	transactionsToRestore := transactions
	v.Node.Mutex.Lock()
	for _, transaction := range transactions {
		if transaction.Verify(v.Node) {
			transactionsToRestore = append(transactionsToRestore, transaction)
		}
	}
	v.Node.Mutex.Unlock()
	v.MemPool.RestoreMemPool(transactionsToRestore)
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

func (v *Validator) CreateBlock(previousBlockHash [32]byte) *blk.Block {
	// Validator does not validate its block since it validated all transactions while adding them to MemPool

	// Takes up to MAX_TRANSACTIONS_IN_BLOCK transactions from beginning of MemPool and create block body with them
	maxNumber := MaxTransactionsInBlock
	blockBody := blk.Body{
		Transactions: v.MemPool.GetWithUpperBound(maxNumber),
	}
	// Create block header
	blockHeader := blk.Header{
		Previous:   previousBlockHash,
		TimeStamp:  uint64(time.Now().Unix()),
		MerkleRoot: merkle_tree.GetMerkleRoot(blockBody.Transactions),
	}

	// Create block itself
	newBlock := &blk.Block{
		Header: blockHeader,
		Body:   blockBody,
	}

	// Sign block
	v.SignAndUpdateBlock(newBlock)

	return newBlock
}

func (v *Validator) SignAndUpdateBlock(block *blk.Block) {
	v.BlockSigner.SignAndUpdateBlock(v.KeyPair, block)
}

func (v *Validator) SignBlock(block *blk.Block) (keys.PublicKeyBytes, ss.SingleSignatureBytes) {
	return v.BlockSigner.SignBlock(v.KeyPair, block)
}

func (v *Validator) VerifyBlock(block *blk.Block) bool {
	prevHashValid := block.Header.Previous == v.Blockchain.GetLastBlockHash()
	v.Node.Mutex.Lock()
	defer v.Node.Mutex.Unlock()
	return prevHashValid && block.Verify(v.Node)
}

func (v *Validator) AddBlockToChain(block *blk.Block) error {
	return v.Blockchain.AddBlock(block)
}

type IndexedDataActualizer interface {
	ActualizeIndexedData(indexedData *repository.IndexedData)
}

func (v *Validator) ActualizeNodeData(block *blk.Block) {
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
		if newTransaction.GetTxType() == tx.AccountCreation &&
			(newTransaction.(*tx.Transaction).PublicKey == keys.PublicKeyBytes{}) {
			signer.NewTransactionSigner().SignTransactionWithPrivateKey(RegAdminPrivateKey, newTransaction.(*tx.Transaction))
		}
		v.TxResponseChannel <- v.AddToMemPool(newTransaction)
	}
}
