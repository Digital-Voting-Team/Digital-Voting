package transactions

import (
	"fmt"
)

type TxAccountCreation struct {
	AccountType    uint8
	NewPubKey      [33]byte
	AdminSignature Signature
	AdminPubKey    [33]byte
}

func NewTxAccCreation(AccountType uint8, NewPubKey [33]byte) *TxAccountCreation {
	return &TxAccountCreation{AccountType: AccountType, NewPubKey: NewPubKey}
}

func (tx *TxAccountCreation) GetStringToSign() string {
	return fmt.Sprintf("%d, %v", tx.AccountType, tx.NewPubKey)
}
