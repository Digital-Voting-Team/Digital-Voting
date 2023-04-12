package transaction

import (
	"digital-voting/account_manager"
	"digital-voting/signature/keys"
)

type TxBody interface {
	GetSignatureMessage() string
	Validate(accountManager *account_manager.AccountManager) bool
	CheckPublicKeyByRole(accountManager *account_manager.AccountManager, publicKey keys.PublicKeyBytes) bool
}
