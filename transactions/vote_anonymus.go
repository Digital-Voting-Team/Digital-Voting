package transactions

type RingSignature string

type voteAnonymousTx struct {
	transactionType uint8
	prevTxHash      [256]byte
	answer          uint8
	signature       RingSignature
	nonce           uint32
}
