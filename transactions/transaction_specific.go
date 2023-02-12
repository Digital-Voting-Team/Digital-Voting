package transactions

type TransactionSpecific interface {
	GetStringToSign() string
}
