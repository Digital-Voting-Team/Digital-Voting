package transactions

import "fmt"

type TxVoteAnonymous struct {
	PrevTxHash [256]byte
	Answer     uint8
	Signature  RingSignature
}

func NewTxVoteAnonymous(PrevTxHash [256]byte, Answer uint8) *TxVoteAnonymous {
	return &TxVoteAnonymous{PrevTxHash: PrevTxHash, Answer: Answer}
}

func (tx *TxVoteAnonymous) GetStringToSign() string {
	return fmt.Sprintf("%v, %d", tx.PrevTxHash, tx.Answer)
}
