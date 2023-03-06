package transactions

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type TxVoteAnonymous struct {
	TxType        uint8      `json:"tx_type"`
	Answer        uint8      `json:"answer"`
	Data          []byte     `json:"data"`
	Nonce         uint32     `json:"nonce"`
	RingSignature [][65]byte `json:"ring_signature"`
	KeyImage      [33]byte   `json:"key_image"`
	PublicKeys    [][33]byte `json:"public_keys"`
}

func (tx *TxVoteAnonymous) Sign(publicKeys [][33]byte, signature [][65]byte, keyImage [33]byte) {
	tx.PublicKeys = publicKeys
	tx.RingSignature = signature
	tx.KeyImage = keyImage
}

func NewTxVoteAnonymous(Answer uint8) *TxVoteAnonymous {
	return &TxVoteAnonymous{Answer: Answer}
}

func (tx *TxVoteAnonymous) GetHash() string {
	hasher := sha256.New()

	bytes := []byte(fmt.Sprintf("%d, %d, %v, %d", tx.TxType, tx.Answer, tx.Data, tx.Nonce))
	hasher.Write(bytes)
	bytes = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(bytes)

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

func (tx *TxVoteAnonymous) String() string {
	str, _ := json.Marshal(tx)
	return string(str)
}
