package account_creation

import "math/rand"

type signature interface {
}

type txAccountCreation struct {
	txType         uint8
	accountType    uint8
	newPubKey      [33]byte
	adminSignature signature
	adminPubKey    [33]byte
	nonce          uint32
}

func newTxAccCreation(txType uint8, accountType uint8, newPubKey [33]byte) *txAccountCreation {
	return &txAccountCreation{txType: txType, accountType: accountType, newPubKey: newPubKey, nonce: rand.Uint32()}
}
