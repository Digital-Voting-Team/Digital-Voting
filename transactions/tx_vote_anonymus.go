package transactions

import (
	signatures "digital-voting/signature/signatures/ring_signature"
	"encoding/json"
	"fmt"
)

type TxVoteAnonymous struct {
	Answer    uint8                    `json:"answer"`
	Signature signatures.RingSignature `json:"signature"`
}

func NewTxVoteAnonymous(Answer uint8) *TxVoteAnonymous {
	return &TxVoteAnonymous{Answer: Answer}
}

func (tx *TxVoteAnonymous) GetStringToSign() string {
	return fmt.Sprintf("%d", tx.Answer)
}

func (tx *TxVoteAnonymous) String() string {
	str, _ := json.Marshal(tx)
	return string(str)
}
