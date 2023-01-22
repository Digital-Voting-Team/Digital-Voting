package block

import (
	"crypto/sha256"
	"encoding/base64"
)

// TODO : add encode, decode, verification

type Block struct {
	Header  Header  `json:"header"`
	Witness Witness `json:"witness"`
	Body    Body    `json:"body"`
}

func (b *Block) Sign(publicKey, signature [33]byte) {
	// TODO : should we verify signature here?

	b.Witness.addSignature(publicKey, signature)
}

func (b *Block) GetHash() string {
	hasher := sha256.New()

	bytes := []byte(b.Header.GetConcatenation())
	hasher.Write(bytes)
	bytes = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(bytes)

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}
