package transaction_specific

import (
	"crypto/sha256"
	"digital-voting/node"
	"digital-voting/node/account_manager"
	"digital-voting/signature/keys"
	ringSignature "digital-voting/signature/signatures/ring_signature"
	tx "digital-voting/transaction"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
)

type TxVoteAnonymous struct {
	TxType        tx.TxType                        `json:"tx_type"`
	VotingLink    [32]byte                         `json:"voting_link"`
	Answer        uint8                            `json:"answer"`
	Data          []byte                           `json:"data"`
	Nonce         uint32                           `json:"nonce"`
	RingSignature ringSignature.RingSignatureBytes `json:"ring_signature"`
	KeyImage      ringSignature.KeyImageBytes      `json:"key_image"`
	PublicKeys    []keys.PublicKeyBytes            `json:"public_keys"`
}

func (tx *TxVoteAnonymous) GetTxType() tx.TxType {
	return tx.TxType
}

func NewTxVoteAnonymous(votingLink [32]byte, answer uint8) *TxVoteAnonymous {
	return &TxVoteAnonymous{TxType: tx.VoteAnonymous, VotingLink: votingLink, Answer: answer, Nonce: uint32(rand.Int())}
}

func (tx *TxVoteAnonymous) Sign(publicKeys []keys.PublicKeyBytes, signature ringSignature.RingSignatureBytes, keyImage ringSignature.KeyImageBytes) {
	tx.PublicKeys = publicKeys
	tx.RingSignature = signature
	tx.KeyImage = keyImage
}

func (tx *TxVoteAnonymous) GetSignatureMessage() string {
	hasher := sha256.New()

	bytes := []byte(fmt.Sprint(tx.TxType, tx.VotingLink, tx.Answer, tx.Data, tx.Nonce))
	hasher.Write(bytes)
	bytes = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(bytes)

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

func (tx *TxVoteAnonymous) String() string {
	str, _ := json.MarshalIndent(tx, "", "\t")
	return string(str)
}

func (tx *TxVoteAnonymous) Print() {
	log.Println(tx)
}

func (tx *TxVoteAnonymous) GetConcatenation() string {
	return fmt.Sprint(tx.TxType, tx.VotingLink, tx.Answer, tx.Data, tx.Nonce, tx.RingSignature, tx.KeyImage, tx.PublicKeys)
}

func (tx *TxVoteAnonymous) GetHashString() string {
	hash := tx.GetHash()

	return base64.URLEncoding.EncodeToString(hash[:])
}

func (tx *TxVoteAnonymous) GetHash() [32]byte {
	hasher := sha256.New()

	bytes := []byte(tx.GetConcatenation())
	hasher.Write(bytes)
	bytes = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(bytes)

	hash := [32]byte{}
	copy(hash[:], hasher.Sum(nil)[:32])

	return hash
}

func (tx *TxVoteAnonymous) IsEqual(otherTransaction *TxVoteAnonymous) bool {
	return tx.GetHash() == otherTransaction.GetHash()
}

func (tx *TxVoteAnonymous) VerifySignature() bool {
	ecdsaRs := ringSignature.NewECDSA_RS()
	return ecdsaRs.VerifyBytes(tx.GetSignatureMessage(), tx.PublicKeys, tx.RingSignature, tx.KeyImage)
}

func (tx *TxVoteAnonymous) CheckOnCreate(node *node.Node) bool {
	// TODO: think of date validation

	indexedVoting := node.VotingProvider.GetVoting(tx.VotingLink)
	if indexedVoting.Hash == [32]byte{} {
		return false
	}

	if tx.Answer < 0 || tx.Answer >= uint8(len(indexedVoting.Answers)) {
		return false
	}

	whiteList := node.VotingProvider.GetVoting(tx.VotingLink).Whitelist

	for _, pubKey := range tx.PublicKeys {
		if !node.AccountManager.CheckPubKeyPresence(pubKey, account_manager.User) {
			return false
		}

		flag := false

		for _, identifier := range whiteList {
			if node.GroupProvider.IsGroupMember(identifier, pubKey) || identifier == pubKey {
				flag = true
				break
			}
		}

		if !flag {
			return false
		}
	}

	return tx.VerifySignature()
}

func (tx *TxVoteAnonymous) GetTxBody() tx.TxBody {
	return nil
}
