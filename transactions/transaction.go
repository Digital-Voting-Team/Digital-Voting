package transactions

type Signature interface {
}

type RingSignature interface {
}

type Transaction struct {
	TxType uint8
	TxBody TransactionBody
	Data   []byte
	Nonce  uint32
}
