package transaction_specific

import (
	"fmt"
)

type TxAccountCreation struct {
	AccountType  uint8    `json:"account_type"`
	NewPublicKey [33]byte `json:"new_public_key"`
}

func NewTxAccCreation(accountType uint8, newPublicKey [33]byte) *TxAccountCreation {
	return &TxAccountCreation{AccountType: accountType, NewPublicKey: newPublicKey}
}

func (tx *TxAccountCreation) GetStringToSign() string {
	return fmt.Sprintf("%d, %v", tx.AccountType, tx.NewPublicKey)
}

func (tx *TxAccountCreation) IsEqual(otherTransaction *TxAccountCreation) bool {
	return tx.AccountType == otherTransaction.AccountType &&
		tx.NewPublicKey == otherTransaction.NewPublicKey
}
