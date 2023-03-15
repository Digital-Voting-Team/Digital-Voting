package transaction_specific

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"reflect"
)

type TxVoteAnonymous struct {
	TxType        uint8      `json:"tx_type"`
	VotingLink    [32]byte   `json:"voting_link"`
	Answer        uint8      `json:"answer"`
	Data          []byte     `json:"data"`
	Nonce         uint32     `json:"nonce"`
	RingSignature [][65]byte `json:"ring_signature"`
	KeyImage      [33]byte   `json:"key_image"`
	PublicKeys    [][33]byte `json:"public_keys"`
}

func (tx *TxVoteAnonymous) GetTxType() uint8 {
	return tx.TxType
}

func NewTxVoteAnonymous(votingLink [32]byte, answer uint8) *TxVoteAnonymous {
	return &TxVoteAnonymous{VotingLink: votingLink, Answer: answer, Nonce: uint32(rand.Int())}
}

func (tx *TxVoteAnonymous) Sign(publicKeys [][33]byte, signature [][65]byte, keyImage [33]byte) {
	tx.PublicKeys = publicKeys
	tx.RingSignature = signature
	tx.KeyImage = keyImage
}

func (tx *TxVoteAnonymous) GetHash() string {
	hasher := sha256.New()

	bytes := []byte(fmt.Sprintf("%d, %v, %d, %v, %d", tx.TxType, tx.VotingLink, tx.Answer, tx.Data, tx.Nonce))
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

func (tx *TxVoteAnonymous) HashString() string {
	hasher := sha256.New()

	bytes := []byte(tx.String())
	hasher.Write(bytes)
	bytes = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(bytes)

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

func (tx *TxVoteAnonymous) IsEqual(otherTransaction *TxVoteAnonymous) bool {
	return tx.TxType == otherTransaction.TxType &&
		tx.Nonce == otherTransaction.Nonce &&
		tx.VotingLink == otherTransaction.VotingLink &&
		tx.Answer == otherTransaction.Answer &&
		reflect.DeepEqual(tx.RingSignature, otherTransaction.RingSignature) &&
		tx.KeyImage == otherTransaction.KeyImage &&
		reflect.DeepEqual(tx.PublicKeys, otherTransaction.PublicKeys)
}
