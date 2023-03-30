package transaction

import "digital-voting/identity_provider"

type ITransaction interface {
	GetHashString() string
	GetHash() [32]byte
	Print()
	GetTxType() TxType
	Validate(identityProvider *identity_provider.IdentityProvider) bool
	VerifySignature() bool
	GetTxBody() TxBody
}
