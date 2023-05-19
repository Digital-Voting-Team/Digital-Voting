package block

import (
	"crypto/sha256"
	"digital-voting/identity_provider"
	"digital-voting/merkle_tree"
	"digital-voting/signature/keys"
	signature "digital-voting/signature/signatures/single_signature"
	tx "digital-voting/transaction"
	"encoding/base64"
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

// TODO : add txs verification
func (b *Block) Verify(identityProvider *identity_provider.IdentityProvider) bool {
	merkleRoot := merkle_tree.GetMerkleRoot(b.Body.Transactions)

	if !b.Witness.Verify(identityProvider, b.GetHashString()) {
		return false
	}

	return merkleRoot == b.Header.MerkleRoot
}
