package block

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/block/merkle_tree"
	tx "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction/transaction_json"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
	signature "github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/signatures/single_signature"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository"
	"time"
)

// TODO : add encode, decode

type Block struct {
	Header  Header  `json:"header"`
	Witness Witness `json:"witness"`
	Body    Body    `json:"body"`
}

func NewBlock(txs []tx.ITransaction, previous [32]byte) *Block {
	blockBody := Body{
		Transactions: txs,
	}

	blockHeader := Header{
		Previous:   previous,
		TimeStamp:  uint64(time.Now().Unix()),
		MerkleRoot: merkle_tree.GetMerkleRoot(blockBody.Transactions),
	}

	block := &Block{
		Header: blockHeader,
		Body:   blockBody,
	}

	return block
}

func (b *Block) Sign(publicKey keys.PublicKeyBytes, signature signature.SingleSignatureBytes) {
	b.Witness.addSignature(publicKey, signature)
}

func (b *Block) AddMerkleRoot(merkleRoot [32]byte) {
	b.Header.MerkleRoot = merkleRoot
}

func (b *Block) GetHash() [32]byte {
	hasher := sha256.New()

	bytes := []byte(b.Header.GetConcatenation())
	hasher.Write(bytes)
	bytes = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(bytes)

	hash := [32]byte{}
	copy(hash[:], hasher.Sum(nil)[:32])

	return hash
}

func (b *Block) GetHashString() string {
	hash := b.GetHash()

	return base64.URLEncoding.EncodeToString(hash[:])
}

func (b *Block) Verify(indexedData *repository.IndexedData) bool {
	merkleRoot := merkle_tree.GetMerkleRoot(b.Body.Transactions)

	if !b.Witness.Verify(indexedData.AccountManager, b.GetHashString()) {
		return false
	}

	for _, transaction := range b.Body.Transactions {
		if !transaction.Verify(indexedData) {
			return false
		}
	}

	return merkleRoot == b.Header.MerkleRoot
}

// UnmarshallBlock unmarshalls the JSON representation of the Block into the Block itself
func UnmarshallBlock(marshalledBlock []byte) (*Block, error) {
	temp := map[string]interface{}{}
	err := json.Unmarshal(marshalledBlock, &temp)
	if err != nil {
		return nil, err
	}

	// Block header and witness are unmarshalled automatically
	unmarshalledBlock := &Block{}
	// Header and Witness are unmarshalled automatically, Body isn't
	_ = json.Unmarshal(marshalledBlock, unmarshalledBlock)
	unmarshalledBlock.Body.Transactions = nil

	// Transactions are unmarshalled through iterative process
	for _, transactions := range temp["body"].(map[string]any)["transactions"].([]any) {
		marshall, err := json.Marshal(transactions)
		if err != nil {
			return nil, err
		}

		iTransaction, err := (&transaction_json.JSONTransaction{}).UnmarshallJSON(marshall)
		if err != nil {
			return nil, err
		}

		unmarshalledBlock.Body.AddTransaction(iTransaction)
	}

	return unmarshalledBlock, nil
}