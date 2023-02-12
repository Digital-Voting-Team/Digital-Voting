package transactions

import "fmt"

type TxVote struct {
	PrevTxHash [256]byte
	Answer     uint8
	Signature  Signature
	PublicKey  [33]byte
}

func NewTxVote(PrevTxHash [256]byte, Answer uint8) *TxVote {
	return &TxVote{PrevTxHash: PrevTxHash, Answer: Answer}
}

func (tx *TxVote) GetStringToSign() string {
	return fmt.Sprintf("%v, %d", tx.PrevTxHash, tx.Answer)
}
