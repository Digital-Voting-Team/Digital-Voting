package transaction

import (
	"digital-voting/account_manager"
	"digital-voting/node"
	"digital-voting/signature/keys"
)

type TxBody interface {
	GetSignatureMessage() string
	CheckOnCreate(node *node.Node) bool
	CheckPublicKeyByRole(accountManager *account_manager.AccountManager, publicKey keys.PublicKeyBytes) bool
}
