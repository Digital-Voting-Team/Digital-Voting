package transactions

import (
	"digital-voting/signature/signatures/single_signature"
	"encoding/json"
	"fmt"
)

type TxAccountCreation struct {
	AccountType    uint8                      `json:"account_type"`
	NewPubKey      [33]byte                   `json:"new_pub_key"`
	AdminSignature signatures.SingleSignature `json:"admin_signature"`
	AdminPubKey    [33]byte                   `json:"admin_pub_key"`
}

func NewTxAccCreation(AccountType uint8, NewPubKey [33]byte) *TxAccountCreation {
	return &TxAccountCreation{AccountType: AccountType, NewPubKey: NewPubKey}
}

func (tx *TxAccountCreation) GetStringToSign() string {
	return fmt.Sprintf("%d, %v", tx.AccountType, tx.NewPubKey)
}

func (tx *TxAccountCreation) String() string {
	str, _ := json.Marshal(tx)
	return string(str)
}
