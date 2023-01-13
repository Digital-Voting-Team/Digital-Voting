package transactions

import (
	"fmt"
	"math/rand"
)

type signature interface {
}

type txAccountCreation struct {
	txType         uint8
	accountType    uint8
	newPubKey      [33]byte
	AdminSignature signature
	AdminPubKey    [33]byte
	nonce          uint32
}

func newTxAccCreation(txType uint8, accountType uint8, newPubKey [33]byte) *txAccountCreation {
	return &txAccountCreation{txType: txType, accountType: accountType, newPubKey: newPubKey, nonce: rand.Uint32()}
}

func (tx *txAccountCreation) getStringToSign() string {
	return fmt.Sprintf("%d, %d, %v, %d", tx.txType, tx.accountType, tx.newPubKey, tx.nonce)
}
