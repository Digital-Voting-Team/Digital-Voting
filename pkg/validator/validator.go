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
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository/indexed_votings"
	"log"
	"time"
)

//var RegAdminPrivateKey = keys.PrivateKeyBytes{1}

const MaxTransactionsInBlock = 5

type ResponseMessage struct {
	VerificationSuccess bool                    `json:"verification_success"`
	PublicKey           keys.PublicKeyBytes     `json:"public_key"`
	Signature           ss.SingleSignatureBytes `json:"signature"`
}

type Validator struct {
	KeyPair     *keys.KeyPair
	MemPool     *MemPool
	IndexedData *repository.IndexedData
	BlockSigner *signer.BlockSigner
	Blockchain  *blockchain.Blockchain

	// TODO: consider optimizing or restructuring channels
	NetworkToValidator   <-chan *blk.Block
	ValidatorToNetwork   chan<- *blk.Block
	BlockResponseChannel chan<- ResponseMessage

	BlockApprovalChannel <-chan *blk.Block
	ApprovalResponseChan chan<- bool

	BlockDenialChannel <-chan *blk.Block

	TransactionChannel <-chan tx.ITransaction
	TxResponseChannel  chan<- bool

	ValidatorKeysChannel <-chan []keys.PublicKeyBytes

	VotingsChannel   chan<- []indexed_votings.VotingDTO
	PublicKeyChannel <-chan keys.PublicKeyBytes
}

func NewValidator(
	bc *blockchain.Blockchain,
	netToValChan <-chan *blk.Block,
	valToNetChan chan<- *blk.Block,
	blockResponseChan chan<- ResponseMessage,
	blockApprovalChan <-chan *blk.Block,
	approvalResponseChan chan<- bool,
	blockDenialChan <-chan *blk.Block,
	transactionChan <-chan tx.ITransaction,
	txResponseChan chan<- bool,
	validatorKeysChan <-chan []keys.PublicKeyBytes,
	votingsChan chan<- []indexed_votings.VotingDTO,
	publicKeyChan <-chan keys.PublicKeyBytes,
) *Validator {
	validatorKeys, err := keys.Random(curve.NewCurve25519())
	if err != nil {
		log.Fatal(err)
	}
	v := &Validator{
		KeyPair:     validatorKeys,
		MemPool:     NewMemPool(),
		IndexedData: repository.NewIndexedData(),
		BlockSigner: signer.NewBlockSigner(),
		Blockchain:  bc,

		NetworkToValidator:   netToValChan,
		ValidatorToNetwork:   valToNetChan,
		BlockResponseChannel: blockResponseChan,

		BlockApprovalChannel: blockApprovalChan,
		ApprovalResponseChan: approvalResponseChan,

		BlockDenialChannel: blockDenialChan,

		TransactionChannel: transactionChan,
		TxResponseChannel:  txResponseChan,

		ValidatorKeysChannel: validatorKeysChan,

		VotingsChannel:   votingsChan,
		PublicKeyChannel: publicKeyChan,
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
	go v.GetVotingsForPubKey()
}

// ValidateBlocks wait for blocks from channel and validate them
func (v *Validator) ValidateBlocks() {
	var response ResponseMessage
	for {
		newBlock := <-v.NetworkToValidator
		if v.VerifyBlock(newBlock) {
			log.Printf("Successfully verified block with hash %s", newBlock.GetHashString())
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
			if err != nil {
				log.Fatalln(err)
			}
			v.ActualizeNodeData(approvedBlock)
			log.Printf("Successfully added block with hash %s", approvedBlock.GetHashString())
			v.ApprovalResponseChan <- true
		}
		log.Println("Block approval failed")
		v.ApprovalResponseChan <- false
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
	v.IndexedData.Mutex.Lock()
	for _, transaction := range transactions {
		if transaction.Verify(v.IndexedData) {
			transactionsToRestore = append(transactionsToRestore, transaction)
		}
	}
	v.IndexedData.Mutex.Unlock()
	v.MemPool.RestoreMemPool(transactionsToRestore)
}

// TODO: get last block hash from blockchain
func (v *Validator) CreateAndSendBlock() {
	ticker := time.NewTicker(time.Second * 10)
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
	v.IndexedData.Mutex.Lock()
	response := newTransaction.CheckOnCreate(v.IndexedData)
	v.IndexedData.Mutex.Unlock()
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
	if block.Header.Previous != v.Blockchain.GetLastBlockHash() || len(block.Body.Transactions) > MaxTransactionsInBlock {
		return false
	}

	v.IndexedData.Mutex.Lock()
	defer v.IndexedData.Mutex.Unlock()
	return block.Verify(v.IndexedData)
}

func (v *Validator) AddBlockToChain(block *blk.Block) error {
	return v.Blockchain.AddBlock(block)
}

type IndexedDataActualizer interface {
	ActualizeIndexedData(indexedData *repository.IndexedData)
}

func (v *Validator) ActualizeNodeData(block *blk.Block) {
	v.IndexedData.Mutex.Lock()
	defer v.IndexedData.Mutex.Unlock()
	for _, transaction := range block.Body.Transactions {
		txExact, ok := transaction.GetTxBody().(IndexedDataActualizer)
		if ok {
			txExact.ActualizeIndexedData(v.IndexedData)
		}
	}
}

func (v *Validator) UpdateValidatorKeys() {
	for {
		newValidatorKeys := <-v.ValidatorKeysChannel
		v.IndexedData.Mutex.Lock()
		v.IndexedData.AccountManager.ValidatorPubKeys = map[keys.PublicKeyBytes]struct{}{}
		for _, key := range newValidatorKeys {
			v.IndexedData.AccountManager.AddPubKey(key, account_manager.Validator)
		}
		v.IndexedData.Mutex.Unlock()
	}
}

func (v *Validator) AddNewTransaction() {
	for {
		newTransaction := <-v.TransactionChannel
		//if newTransaction.GetTxType() == tx.AccountCreation &&
		//	(newTransaction.(*tx.Transaction).PublicKey == keys.PublicKeyBytes{}) {
		//	signer.NewTransactionSigner().SignTransactionWithPrivateKey(RegAdminPrivateKey, newTransaction.(*tx.Transaction))
		//}
		v.TxResponseChannel <- v.AddToMemPool(newTransaction)
	}
}

func (v *Validator) GetVotingsForPubKey() {
	for {
		pubKey := <-v.PublicKeyChannel

		result := []indexed_votings.VotingDTO{}

		votings := v.IndexedData.VotingManager.IndexedVotings

		for _, voting := range votings {
			flag := false
			whiteList := voting.Whitelist
			for _, identifier := range whiteList {
				if v.IndexedData.GroupManager.IsGroupMember(identifier, pubKey) || identifier == pubKey {
					result = append(result, voting)
					flag = true
					break
				}
			}
			if flag {
				continue
			}
		}

		v.VotingsChannel <- result
	}
}
