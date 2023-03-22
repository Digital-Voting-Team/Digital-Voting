package transaction

import "digital-voting/identity_provider"

// ITransaction TODO: think of moving interface into packages for their specific purposes (merkle_tree, block etc.)
type ITransaction interface {
	GetHash() string
	Print()
	GetTxType() TxType
	Validate(identityProvider *identity_provider.IdentityProvider) bool
}
