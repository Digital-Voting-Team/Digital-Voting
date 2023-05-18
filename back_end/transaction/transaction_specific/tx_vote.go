package transaction_specific

import (
	"crypto/sha256"
	"digital-voting/node"
	"digital-voting/node/account_manager"
	"digital-voting/signature/keys"
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
	return fmt.Sprint(tx.VotingLink, tx.Answer)
}

func (tx *TxVote) String() string {
	str, _ := json.Marshal(tx)
	return string(str)
}

func (tx *TxVote) GetHashString() string {
	hash := tx.GetHash()

	return base64.URLEncoding.EncodeToString(hash[:])
}

func (tx *TxVote) GetHash() [32]byte {
	hasher := sha256.New()

	bytes := []byte(tx.GetSignatureMessage())
	hasher.Write(bytes)
	bytes = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(bytes)

	hash := [32]byte{}
	copy(hash[:], hasher.Sum(nil)[:32])

	return hash
}

func (tx *TxVote) IsEqual(otherTransaction *TxVote) bool {
	return tx.GetHash() == otherTransaction.GetHash()
}

func (tx *TxVote) CheckPublicKeyByRole(accountManager *account_manager.AccountManager, publicKey keys.PublicKeyBytes) bool {
	return accountManager.CheckPubKeyPresence(publicKey, account_manager.User)
}

func (tx *TxVote) CheckOnCreate(node *node.Node) bool {
	// TODO: think of date validation

	indexedVoting := node.VotingProvider.GetVoting(tx.VotingLink)
	if indexedVoting.Hash == [32]byte{} {
		return false
	}

	if tx.Answer < 0 || tx.Answer >= uint8(len(indexedVoting.Answers)) {
		return false
	}

	return true
}
