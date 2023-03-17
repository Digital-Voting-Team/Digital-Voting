package transaction_specific

import (
	"crypto/sha256"
	"digital-voting/identity_provider"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

func (tx *TxVotingCreation) GetHash() string {
	hasher := sha256.New()

	bytes := []byte(tx.String())
	hasher.Write(bytes)
	bytes = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(bytes)

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

func (tx *TxVotingCreation) IsEqual(otherTransaction *TxAccountCreation) bool {
	return tx.GetHash() == otherTransaction.GetHash()
}

func (tx *TxVotingCreation) CheckPublicKeyByRole(identityProvider *identity_provider.IdentityProvider, publicKey [33]byte) bool {
	return identityProvider.CheckPubKeyPresence(publicKey, identity_provider.VotingCreationAdmin)
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
