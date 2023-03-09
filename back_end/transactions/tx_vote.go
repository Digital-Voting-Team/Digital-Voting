package transactions

import (
	"encoding/json"
	"fmt"
)

type TxVote struct {
	VotingLink [32]byte `json:"voting_link"`
	Answer     uint8    `json:"answer"`
}

func NewTxVote(VotingLink [32]byte, Answer uint8) *TxVote {
	return &TxVote{VotingLink: VotingLink, Answer: Answer}
}

func (tx *TxVote) GetStringToSign() string {
	return fmt.Sprintf("%v, %d", tx.VotingLink, tx.Answer)
}

func (tx *TxVote) String() string {
	str, _ := json.Marshal(tx)
	return string(str)
}
