package transaction

import (
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository"
)

type TxBody interface {
	GetSignatureMessage() string
	CheckOnCreate(indexedData *repository.IndexedData, publicKey keys.PublicKeyBytes) bool
	Verify(indexedData *repository.IndexedData, publicKey keys.PublicKeyBytes) bool
	CheckPublicKeyByRole(indexedData *repository.IndexedData, publicKey keys.PublicKeyBytes) bool
}
