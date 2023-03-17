package transaction_specific

import (
	"digital-voting/identity_provider"
	"fmt"
)

type TxVote struct {
	VotingLink [32]byte `json:"voting_link"`
	Answer     uint8    `json:"answer"`
}

func NewTxVote(votingLink [32]byte, answer uint8) *TxVote {
	return &TxVote{VotingLink: votingLink, Answer: answer}
}

func (tx *TxVote) GetSignatureMessage() string {
	return fmt.Sprintf("%v, %d", tx.VotingLink, tx.Answer)
}

func (tx *TxVote) IsEqual(otherTransaction *TxVote) bool {
	return tx.VotingLink == otherTransaction.VotingLink &&
		tx.Answer == otherTransaction.Answer
}

func (tx *TxVote) Validate(identityProvider *identity_provider.IdentityProvider, publicKey [33]byte) bool {
	if !identityProvider.CheckPubKeyPresence(publicKey, identity_provider.User) {
		return false
	}

	// TODO: add a way of getting voting by its link to check connected data
	return true
}
