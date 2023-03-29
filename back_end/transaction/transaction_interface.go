package transaction

import "digital-voting/identity_provider"

type ITransaction interface {
	GetHash() string
	Print()
	GetTxType() TxType
	Validate(identityProvider *identity_provider.IdentityProvider) bool
	VerifySignature() bool
	GetTxBody() TxBody
}
