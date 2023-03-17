package transaction_specific

import (
	"crypto/sha256"
	"digital-voting/identity_provider"
	"encoding/base64"
	"encoding/json"
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

func (tx *TxAccountCreation) String() string {
	str, _ := json.Marshal(tx)
	return string(str)
}

func (tx *TxAccountCreation) GetHash() string {
	hasher := sha256.New()

	bytes := []byte(tx.String())
	hasher.Write(bytes)
	bytes = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(bytes)

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

func (tx *TxAccountCreation) IsEqual(otherTransaction *TxAccountCreation) bool {
	return tx.GetHash() == otherTransaction.GetHash()
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
