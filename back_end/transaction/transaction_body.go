package transaction

import (
	"digital-voting/node"
	"digital-voting/signature/keys"
)

type TxBody interface {
	GetSignatureMessage() string
	CheckOnCreate(node *node.Node, publicKey keys.PublicKeyBytes) bool
	Verify(node *node.Node, publicKey keys.PublicKeyBytes) bool
	CheckPublicKeyByRole(node *node.Node, publicKey keys.PublicKeyBytes) bool
}
