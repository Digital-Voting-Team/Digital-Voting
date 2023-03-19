package transaction_specific

import (
	"crypto/sha256"
	"digital-voting/identity_provider"
	"encoding/base64"
	"encoding/json"
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
	return fmt.Sprintf("%v%d", tx.VotingLink, tx.Answer)
}

func (tx *TxVote) String() string {
	str, _ := json.Marshal(tx)
	return string(str)
}

func (tx *TxVote) GetHash() string {
	hasher := sha256.New()

	bytes := []byte(tx.GetSignatureMessage())
	hasher.Write(bytes)
	bytes = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(bytes)

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

func (tx *TxVote) IsEqual(otherTransaction *TxVote) bool {
	return tx.GetHash() == otherTransaction.GetHash()
}

func (tx *TxVote) CheckPublicKeyByRole(identityProvider *identity_provider.IdentityProvider, publicKey [33]byte) bool {
	return identityProvider.CheckPubKeyPresence(publicKey, identity_provider.User)
}

func (tx *TxVote) Validate(identityProvider *identity_provider.IdentityProvider) bool {
	// TODO: add a way of getting voting by its link to check connected data
	return true
}
