package transaction

import (
	"digital-voting/identity_provider"
	"digital-voting/signature/keys"
)

type TxBody interface {
	GetSignatureMessage() string
	Validate(identityProvider *identity_provider.IdentityProvider) bool
	CheckPublicKeyByRole(identityProvider *identity_provider.IdentityProvider, publicKey keys.PublicKeyBytes) bool
	ActualizeIndexedData(identityProvider *identity_provider.IdentityProvider)
}
