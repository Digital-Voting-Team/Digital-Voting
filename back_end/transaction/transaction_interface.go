package transaction

import (
	"digital-voting/node"
)

type ITransaction interface {
	GetHashString() string
	GetHash() [32]byte
	Print()
	GetTxType() TxType
	CheckOnCreate(node *node.Node) bool
	VerifySignature() bool
	GetTxBody() TxBody
}
