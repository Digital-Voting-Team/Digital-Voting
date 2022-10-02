package transactions

type voteTx struct {
	transactionType uint8
	prevTxHash      [256]byte
	answer          uint8
	signature       Signature
	publicKey       Address
	nonce           uint32
}
