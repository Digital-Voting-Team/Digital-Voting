package transaction_specific

import (
	"fmt"
)

type TxVote struct {
	VotingLink [32]byte `json:"voting_link"`
	Answer     uint8    `json:"answer"`
}

func NewTxVote(votingLink [32]byte, answer uint8) *TxVote {
	return &TxVote{VotingLink: votingLink, Answer: answer}
}

func (tx *TxVote) GetStringToSign() string {
	return fmt.Sprintf("%v, %d", tx.VotingLink, tx.Answer)
}

func (tx *TxVote) IsEqual(otherTransaction *TxVote) bool {
	return tx.VotingLink == otherTransaction.VotingLink &&
		tx.Answer == otherTransaction.Answer
}
