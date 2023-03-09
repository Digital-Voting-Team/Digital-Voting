package transaction

type TxBody interface {
	GetStringToSign() string
}
