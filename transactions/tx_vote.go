package transactions

import "fmt"

type txVote struct {
	txType     uint8
	prevTxHash [256]byte
	answer     uint8
	Signature  Signature
	PublicKey  Address
	nonce      uint32
}

func newTxVote(txType uint8, prevTxHash [256]byte, answer uint8, nonce uint32) *txVote {
	return &txVote{txType: txType, prevTxHash: prevTxHash, answer: answer, nonce: nonce}
}

func (tx *txVote) GetStringToSign() string {
	return fmt.Sprintf("%d, %v, %d, %d", tx.txType, tx.prevTxHash, tx.answer, tx.nonce)
}
