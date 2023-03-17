package transaction

import "digital-voting/identity_provider"

type TxBody interface {
	GetSignatureMessage() string
	Validate(identityProvider *identity_provider.IdentityProvider, publicKey [33]byte) bool
}
