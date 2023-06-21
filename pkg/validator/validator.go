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

	Channels Communication
}

func NewValidator(
	bc *blockchain.Blockchain,
	channels Communication,
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

		Channels: channels,
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
		newBlock := <-v.Channels.NetworkToValidator
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
		v.Channels.BlockResponse <- response
	}
}

// ApproveBlock wait for transactions from channel, approve and add them to blockchain
func (v *Validator) ApproveBlock() {
	for {
		approvedBlock := <-v.Channels.BlockApproval
		log.Printf("Block with hash %s received to approve", approvedBlock.GetHashString())
		if v.VerifyBlock(approvedBlock) {
			err := v.AddBlockToChain(approvedBlock)
			if err != nil {
				log.Fatalln(err)
			}
			v.ActualizeNodeData(approvedBlock)
			v.Channels.ApprovalResponse <- true
			log.Printf("Block with hash %s added", approvedBlock.GetHashString())
		} else {
			v.Channels.ApprovalResponse <- false
		}
	}
}

// DenyBlock wait for transactions from channel, restore transactions from it
func (v *Validator) DenyBlock() {
	for {
		deniedBlock := <-v.Channels.BlockDenial
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
				v.Channels.ValidatorToNetwork <- v.CreateBlock(hash)
			}
		default:
			hash := v.Blockchain.GetLastBlockHash()
			if v.MemPool.GetTransactionsCount() >= MaxTransactionsInBlock {
				v.Channels.ValidatorToNetwork <- v.CreateBlock(hash)
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
		newValidatorKeys := <-v.Channels.ValidatorKeys
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
		newTransaction := <-v.Channels.Transaction
		// TODO: uncomment in case of demo without administrators
		//if newTransaction.GetTxType() == tx.AccountCreation &&
		//	(newTransaction.(*tx.Transaction).PublicKey == keys.PublicKeyBytes{}) {
		//	signer.NewTransactionSigner().SignTransactionWithPrivateKey(RegAdminPrivateKey, newTransaction.(*tx.Transaction))
		//}
		v.Channels.TxResponse <- v.AddToMemPool(newTransaction)
	}
}

func (v *Validator) GetVotingsForPubKey() {
	for {
		pubKey := <-v.Channels.PublicKey

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

		v.Channels.Votings <- result
	}
}
