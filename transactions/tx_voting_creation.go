package transactions

import (
	"encoding/json"
	"fmt"
)

type TxVotingCreation struct {
	ExpirationDate    uint32      `json:"expiration_date"`
	VotingDescription [1024]byte  `json:"voting_description"`
	Answers           [][256]byte `json:"answers"`
	Whitelist         [][33]byte  `json:"whitelist"`
}

func NewTxVotingCreation(ExpirationDate uint32, VotingDescription [1024]byte, Answers [][256]byte, Whitelist [][33]byte) *TxVotingCreation {
	return &TxVotingCreation{ExpirationDate: ExpirationDate, VotingDescription: VotingDescription, Answers: Answers, Whitelist: Whitelist}
}

func (tx *TxVotingCreation) GetStringToSign() string {
	return fmt.Sprintf("%d, %v, %v, %v", tx.ExpirationDate, tx.VotingDescription, tx.Answers, tx.Whitelist)
}

func (tx *TxVotingCreation) String() string {
	str, _ := json.Marshal(tx)
	return string(str)
}
