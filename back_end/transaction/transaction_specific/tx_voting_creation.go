package transaction_specific

import (
	"digital-voting/identity_provider"
	"encoding/json"
	"fmt"
	"reflect"
	"time"
)

type TxVotingCreation struct {
	ExpirationDate    uint32      `json:"expiration_date"`
	VotingDescription [1024]byte  `json:"voting_description"`
	Answers           [][256]byte `json:"answers"`
	Whitelist         [][33]byte  `json:"whitelist"`
}

func NewTxVotingCreation(expirationDate time.Time, votingDescription string, answers []string, whitelist [][33]byte) *TxVotingCreation {
	expDate := uint32(expirationDate.Unix())

	votingDescr := [1024]byte{}
	copy(votingDescr[:], votingDescription)

	ans := make([][256]byte, len(answers))
	for i, answer := range answers {
		copy(ans[i][:], answer)
	}

	return &TxVotingCreation{ExpirationDate: expDate, VotingDescription: votingDescr, Answers: ans, Whitelist: whitelist}
}

func (tx *TxVotingCreation) GetSignatureMessage() string {
	return fmt.Sprintf("%d, %v, %v, %v", tx.ExpirationDate, tx.VotingDescription, tx.Answers, tx.Whitelist)
}

func (tx *TxVotingCreation) String() string {
	str, _ := json.Marshal(tx)
	return string(str)
}

func (tx *TxVotingCreation) IsEqual(otherTransaction *TxVotingCreation) bool {
	return tx.ExpirationDate == otherTransaction.ExpirationDate &&
		tx.VotingDescription == otherTransaction.VotingDescription &&
		reflect.DeepEqual(tx.Answers, otherTransaction.Answers) &&
		reflect.DeepEqual(tx.Whitelist, otherTransaction.Whitelist)
}

func (tx *TxVotingCreation) Validate(identityProvider *identity_provider.IdentityProvider) bool {
	// TODO: think of date validation
	for _, pubKey := range tx.Whitelist {
		if !identityProvider.CheckPubKeyPresence(pubKey, identity_provider.User) {
			return false
		}
	}
	return true
}
