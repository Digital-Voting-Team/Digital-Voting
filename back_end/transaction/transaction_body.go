package transaction

import (
	"digital-voting/account_manager"
	"digital-voting/signature/keys"
)

type TxBody interface {
	GetSignatureMessage() string
	Validate(identityProvider *account_manager.AccountManager) bool
	CheckPublicKeyByRole(identityProvider *account_manager.AccountManager, publicKey keys.PublicKeyBytes) bool
}
