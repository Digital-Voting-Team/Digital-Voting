package transaction_specific

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository/account_manager"
	"time"
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

func (tx *TxVote) CheckPublicKeyByRole(indexedData *repository.IndexedData, publicKey keys.PublicKeyBytes) bool {
	if !indexedData.AccountManager.CheckPubKeyPresence(publicKey, account_manager.User) {
		return false
	}

	whiteList := indexedData.VotingManager.GetVoting(tx.VotingLink).Whitelist
	for identifier, _ := range whiteList {
		if indexedData.GroupManager.IsGroupMember(identifier, publicKey) || identifier == publicKey {
			return true
		}
	}

	return false
}

func (tx *TxVote) checkData(indexedData *repository.IndexedData) bool {
	indexedVoting := indexedData.VotingManager.GetVoting(tx.VotingLink)
	if indexedVoting.Hash == [32]byte{} {
		return false
	}

	if uint32(time.Now().Unix()) > indexedVoting.ExpirationDate || tx.Answer < 0 || tx.Answer >= uint8(len(indexedVoting.Answers)) {
		return false
	}

	return true
}

func (tx *TxVote) CheckOnCreate(indexedData *repository.IndexedData, publicKey keys.PublicKeyBytes) bool {
	return tx.checkData(indexedData) && tx.CheckPublicKeyByRole(indexedData, publicKey)
}

func (tx *TxVote) Verify(indexedData *repository.IndexedData, publicKey keys.PublicKeyBytes) bool {
	return tx.checkData(indexedData) && tx.CheckPublicKeyByRole(indexedData, publicKey)
}
