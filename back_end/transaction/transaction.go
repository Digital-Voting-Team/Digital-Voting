package transaction

import (
	"crypto/sha256"
	"digital-voting/node"
	"digital-voting/signature/keys"
	singleSignature "digital-voting/signature/signatures/single_signature"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
)

type TxType uint8

const (
	AccountCreation TxType = iota
	GroupCreation
	VotingCreation
	Vote
	VoteAnonymous
)

type Transaction struct {
	TxType    TxType                               `json:"tx_type"`
	TxBody    TxBody                               `json:"tx_body"`
	Data      []byte                               `json:"data"`
	Nonce     uint32                               `json:"nonce"`
	Signature singleSignature.SingleSignatureBytes `json:"signature"`
	PublicKey keys.PublicKeyBytes                  `json:"public_key"`
}

func (tx *Transaction) GetTxType() TxType {
	return tx.TxType
}

func (tx *Transaction) Sign(publicKey keys.PublicKeyBytes, signature singleSignature.SingleSignatureBytes) {
	tx.Signature = signature
	tx.PublicKey = publicKey
}

func NewTransaction(txType TxType, txBody TxBody) *Transaction {
	return &Transaction{TxType: txType, TxBody: txBody, Nonce: uint32(rand.Int())}
}

func (tx *Transaction) GetSignatureMessage() string {
	hasher := sha256.New()

	bytes := []byte(fmt.Sprint(tx.TxType, tx.TxBody.GetSignatureMessage(), tx.Data, tx.Nonce))
	hasher.Write(bytes)
	bytes = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(bytes)

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

func (tx *Transaction) String() string {
	str, _ := json.MarshalIndent(tx, "", "\t")
	return string(str)
}

func (tx *Transaction) Print() {
	log.Println(tx)
}

func (tx *Transaction) GetConcatenation() string {
	return fmt.Sprint(tx.TxType, tx.TxBody.GetSignatureMessage(), tx.Data, tx.Nonce, tx.Signature, tx.PublicKey)
}

func (tx *Transaction) GetHashString() string {
	hash := tx.GetHash()

	return base64.URLEncoding.EncodeToString(hash[:])
}

func (tx *Transaction) GetHash() [32]byte {
	hasher := sha256.New()

	bytes := []byte(tx.GetConcatenation())
	hasher.Write(bytes)
	bytes = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(bytes)

	hash := [32]byte{}
	copy(hash[:], hasher.Sum(nil)[:32])

	return hash
}

func (tx *Transaction) IsEqual(otherTransaction *Transaction) bool {
	return tx.GetHash() == otherTransaction.GetHash()
}

func (tx *Transaction) VerifySignature() bool {
	// TODO: think of passing this instead of creating
	ecdsa := singleSignature.NewECDSA()
	return ecdsa.VerifyBytes(
		tx.GetSignatureMessage(),
		tx.PublicKey,
		tx.Signature,
	)
}

func (tx *Transaction) CheckOnCreate(node *node.Node) bool {
	if !tx.TxBody.CheckOnCreate(node) || !tx.TxBody.CheckPublicKeyByRole(node.AccountManager, tx.PublicKey) {
		return false
	}

	return tx.VerifySignature()
}

func (tx *Transaction) GetTxBody() TxBody {
	return tx.TxBody
}
