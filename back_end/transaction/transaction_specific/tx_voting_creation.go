package transaction_specific

import (
	"crypto/sha256"
	"digital-voting/node"
	"digital-voting/node/account_manager"
	"digital-voting/node/indexed_data"
	"digital-voting/signature/keys"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type TxVotingCreation struct {
	ExpirationDate    uint32      `json:"expiration_date"`
	VotingDescription [1024]byte  `json:"voting_description"`
	Answers           [][256]byte `json:"answers"`
	// Not a keys.PublicKeyBytes since it can be group identifier as well
	Whitelist [][33]byte `json:"whitelist"`
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
	return fmt.Sprint(tx.ExpirationDate, tx.VotingDescription, tx.Answers, tx.Whitelist)
}

func (tx *TxVotingCreation) String() string {
	str, _ := json.Marshal(tx)
	return string(str)
}

func (tx *TxVotingCreation) GetHashString() string {
	hash := tx.GetHash()

	return base64.URLEncoding.EncodeToString(hash[:])
}

func (tx *TxVotingCreation) GetHash() [32]byte {
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

func (tx *TxVotingCreation) IsEqual(otherTransaction *TxAccountCreation) bool {
	return tx.GetHash() == otherTransaction.GetHash()
}

func (tx *TxVotingCreation) CheckPublicKeyByRole(node *node.Node, publicKey keys.PublicKeyBytes) bool {
	return node.AccountManager.CheckPubKeyPresence(publicKey, account_manager.VotingCreationAdmin)
}

func (tx *TxVotingCreation) CheckOnCreate(node *node.Node) bool {
	// TODO: think of date validation
	for _, pubKey := range tx.Whitelist {
		if !node.AccountManager.CheckPubKeyPresence(pubKey, account_manager.User) &&
			!node.AccountManager.CheckPubKeyPresence(pubKey, account_manager.GroupIdentifier) {
			return false
		}
	}
	return true
}

func (tx *TxVotingCreation) ActualizeIdentities(node *node.Node) {
	node.VotingProvider.AddNewVoting(indexed_data.VotingDTO{
		Hash:              tx.GetHash(),
		ExpirationDate:    tx.ExpirationDate,
		VotingDescription: tx.VotingDescription,
		Answers:           tx.Answers,
		Whitelist:         tx.Whitelist,
	})
}
