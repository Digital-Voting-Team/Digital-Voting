package transactions

import "fmt"

type TxVotingCreation struct {
	ExpirationDate    uint32
	VotingDescription [1024]byte
	Answers           [][256]byte
	Whitelist         [][33]byte
	AdminSignature    Signature
	AdminPubKey       [33]byte
}

func NewTxVotingCreation(ExpirationDate uint32, VotingDescription [1024]byte, Answers [][256]byte, Whitelist [][33]byte) *TxVotingCreation {
	return &TxVotingCreation{ExpirationDate: ExpirationDate, VotingDescription: VotingDescription, Answers: Answers, Whitelist: Whitelist}
}

func (tx *TxVotingCreation) GetStringToSign() string {
	return fmt.Sprintf("%d, %v, %v, %v", tx.ExpirationDate, tx.VotingDescription, tx.Answers, tx.Whitelist)
}
