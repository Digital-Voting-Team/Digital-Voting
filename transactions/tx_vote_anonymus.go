package transactions

import "fmt"

type RingSignature string

type txVoteAnonymous struct {
	txType     uint8
	prevTxHash [256]byte
	answer     uint8
	Signature  RingSignature
	nonce      uint32
}

func newTxVoteAnonymous(txType uint8, prevTxHash [256]byte, answer uint8, nonce uint32) *txVoteAnonymous {
	return &txVoteAnonymous{txType: txType, prevTxHash: prevTxHash, answer: answer, nonce: nonce}
}

func (tx *txVoteAnonymous) GetStringToSign() string {
	return fmt.Sprintf("%d, %v, %d, %d", tx.txType, tx.prevTxHash, tx.answer, tx.nonce)
}
