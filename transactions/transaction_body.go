package transactions

type TransactionBody interface {
	GetStringToSign()
}
