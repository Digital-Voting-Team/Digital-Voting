package transactions

import (
	"encoding/json"
	"fmt"
)

type TxVote struct {
	Answer    uint8     `json:"answer"`
	Signature Signature `json:"signature"`
	PublicKey [33]byte  `json:"public_key"`
}

func NewTxVote(Answer uint8) *TxVote {
	return &TxVote{Answer: Answer}
}

func (tx *TxVote) GetStringToSign() string {
	return fmt.Sprintf("%d", tx.Answer)
}

func (tx *TxVote) String() string {
	str, _ := json.Marshal(tx)
	return string(str)
}