package transaction

import (
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository"
)

type ITransaction interface {
	GetHashString() string
	GetHash() [32]byte
	Print()
	GetTxType() TxType
	CheckOnCreate(indexedData *repository.IndexedData) bool
	Verify(indexedData *repository.IndexedData) bool
	VerifySignature() bool
	GetTxBody() TxBody
}
