package transactions

import (
	"digital-voting/signature/curve"
	signatures "digital-voting/signature/signatures/single_signature"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
)

type Transaction struct {
	TxType    uint8                      `json:"tx_type"`
	TxBody    TransactionSpecific        `json:"tx_body"`
	Data      []byte                     `json:"data"`
	Nonce     uint32                     `json:"nonce"`
	Signature signatures.SingleSignature `json:"signature"`
	PublicKey curve.Point                `json:"public_key"`
}

func NewTransaction(txType uint8, txBody TransactionSpecific) *Transaction {
	return &Transaction{TxType: txType, TxBody: txBody, Nonce: uint32(rand.Int())}
}

func (tx *Transaction) GetStringToSign() string {
	return fmt.Sprintf("%d, %s, %v, %d", tx.TxType, tx.TxBody.GetStringToSign(), tx.Data, tx.Nonce)
}

func (tx *Transaction) String() string {
	str, _ := json.Marshal(tx)
	return string(str)
}

func (tx *Transaction) Print() {
	log.Println(tx)
}

func (tx *Transaction) IsEqual(otherTransaction *Transaction) bool {
	return tx.TxType == otherTransaction.TxType &&
		tx.Nonce == otherTransaction.Nonce &&
		tx.TxBody == otherTransaction.TxBody &&
		tx.Signature == otherTransaction.Signature &&
		tx.PublicKey == otherTransaction.PublicKey
}
