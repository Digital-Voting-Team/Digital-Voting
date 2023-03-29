package transaction_specific

import (
	"crypto/sha256"
	"digital-voting/identity_provider"
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

func (tx *TxVoteAnonymous) GetHash() string {
	hasher := sha256.New()

	bytes := []byte(tx.GetConcatenation())
	hasher.Write(bytes)
	bytes = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(bytes)

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

func (tx *TxVoteAnonymous) IsEqual(otherTransaction *TxVoteAnonymous) bool {
	return tx.GetHash() == otherTransaction.GetHash()
}

func (tx *TxVoteAnonymous) VerifySignature() bool {
	ecdsaRs := ringSignature.NewECDSA_RS()
	return ecdsaRs.VerifyBytes(tx.GetSignatureMessage(), tx.PublicKeys, tx.RingSignature, tx.KeyImage)
}

func (tx *TxVoteAnonymous) Validate(identityProvider *identity_provider.IdentityProvider) bool {
	// TODO: add a way of getting voting by its link to check connected data
	for _, pubKey := range tx.PublicKeys {
		if !identityProvider.CheckPubKeyPresence(pubKey, identity_provider.User) {
			return false
		}
	}

	return tx.VerifySignature()
}

func (tx *TxVoteAnonymous) GetTxBody() tx.TxBody {
	return nil
}
