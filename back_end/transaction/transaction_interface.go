package transaction

import "digital-voting/account_manager"

type ITransaction interface {
	GetHashString() string
	GetHash() [32]byte
	Print()
	GetTxType() TxType
	Validate(identityProvider *account_manager.AccountManager) bool
	VerifySignature() bool
	GetTxBody() TxBody
}
