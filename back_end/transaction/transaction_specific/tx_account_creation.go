package transaction_specific

import (
	"digital-voting/identity_provider"
	"fmt"
)

type TxAccountCreation struct {
	AccountType  uint8    `json:"account_type"`
	NewPublicKey [33]byte `json:"new_public_key"`
}

func NewTxAccCreation(accountType uint8, newPublicKey [33]byte) *TxAccountCreation {
	return &TxAccountCreation{AccountType: accountType, NewPublicKey: newPublicKey}
}

func (tx *TxAccountCreation) GetSignatureMessage() string {
	return fmt.Sprintf("%d, %v", tx.AccountType, tx.NewPublicKey)
}

func (tx *TxAccountCreation) IsEqual(otherTransaction *TxAccountCreation) bool {
	return tx.AccountType == otherTransaction.AccountType &&
		tx.NewPublicKey == otherTransaction.NewPublicKey
}

func (tx *TxAccountCreation) CheckPublicKeyByRole(identityProvider *identity_provider.IdentityProvider, publicKey [33]byte) bool {
	return identityProvider.CheckPubKeyPresence(publicKey, identity_provider.RegistrationAdmin)
}

func (tx *TxAccountCreation) Validate(identityProvider *identity_provider.IdentityProvider) bool {
	// TODO: think of a better way to check
	return !identityProvider.CheckPubKeyPresence(tx.NewPublicKey, identity_provider.User) &&
		!identityProvider.CheckPubKeyPresence(tx.NewPublicKey, identity_provider.RegistrationAdmin) &&
		!identityProvider.CheckPubKeyPresence(tx.NewPublicKey, identity_provider.VotingCreationAdmin) &&
		!identityProvider.CheckPubKeyPresence(tx.NewPublicKey, identity_provider.GroupIdentifier)
}
