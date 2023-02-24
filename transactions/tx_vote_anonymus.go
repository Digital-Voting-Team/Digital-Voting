package transactions

import (
	signatures "digital-voting/signature/signatures/ring_signature"
	"encoding/json"
	"fmt"
)

type TxVoteAnonymous struct {
	TxType        uint8                    `json:"tx_type"`
	Answer        uint8                    `json:"answer"`
	Data          []byte                   `json:"data"`
	Nonce         uint32                   `json:"nonce"`
	RingSignature signatures.RingSignature `json:"ring_signature"`
}

func NewTxVoteAnonymous(Answer uint8) *TxVoteAnonymous {
	return &TxVoteAnonymous{Answer: Answer}
}

func (tx *TxVoteAnonymous) GetStringToSign() string {
	return fmt.Sprintf("%d, %d, %v, %d", tx.TxType, tx.Answer, tx.Data, tx.Nonce)
}

func (tx *TxVoteAnonymous) String() string {
	str, _ := json.Marshal(tx)
	return string(str)
}
