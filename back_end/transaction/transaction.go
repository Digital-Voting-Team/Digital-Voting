package transaction

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
)

type Transaction struct {
	TxType    uint8    `json:"tx_type"`
	TxBody    TxBody   `json:"tx_body"`
	Data      []byte   `json:"data"`
	Nonce     uint32   `json:"nonce"`
	Signature [65]byte `json:"signature"`
	PublicKey [33]byte `json:"public_key"`
}

func (tx *Transaction) GetTxType() uint8 {
	return tx.TxType
}

func (tx *Transaction) Sign(publicKey [33]byte, signature [65]byte) {
	tx.Signature = signature
	tx.PublicKey = publicKey
}

func NewTransaction(txType uint8, txBody TxBody) *Transaction {
	return &Transaction{TxType: txType, TxBody: txBody, Nonce: uint32(rand.Int())}
}

func (tx *Transaction) GetHash() string {
	hasher := sha256.New()

	bytes := []byte(fmt.Sprintf("%d, %s, %v, %d", tx.TxType, tx.TxBody.GetStringToSign(), tx.Data, tx.Nonce))
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

func (tx *Transaction) HashString() string {
	hasher := sha256.New()

	bytes := []byte(tx.String())
	hasher.Write(bytes)
	bytes = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(bytes)

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

func (tx *Transaction) IsEqual(otherTransaction *Transaction) bool {
	return tx.TxType == otherTransaction.TxType &&
		tx.Nonce == otherTransaction.Nonce &&
		tx.TxBody == otherTransaction.TxBody &&
		tx.Signature == otherTransaction.Signature &&
		tx.PublicKey == otherTransaction.PublicKey
}