package transaction_specific

import (
	"crypto/sha256"
	"digital-voting/account"
	"digital-voting/identity_provider"
	"digital-voting/signature/keys"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type TxAccountCreation struct {
	AccountType  account.Type        `json:"account_type"`
	NewPublicKey keys.PublicKeyBytes `json:"new_public_key"`
}

func NewTxAccCreation(accountType account.Type, newPublicKey keys.PublicKeyBytes) *TxAccountCreation {
	return &TxAccountCreation{AccountType: accountType, NewPublicKey: newPublicKey}
}

func (tx *TxAccountCreation) GetSignatureMessage() string {
	return fmt.Sprint(tx.AccountType, tx.NewPublicKey)
}

func (tx *TxAccountCreation) String() string {
	str, _ := json.Marshal(tx)
	return string(str)
}

func (tx *TxAccountCreation) GetHash() string {
	hasher := sha256.New()

	bytes := []byte(tx.GetSignatureMessage())
	hasher.Write(bytes)
	bytes = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(bytes)

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

func (tx *TxAccountCreation) IsEqual(otherTransaction *TxAccountCreation) bool {
	return tx.GetHash() == otherTransaction.GetHash()
}

func (tx *TxAccountCreation) CheckPublicKeyByRole(identityProvider *identity_provider.IdentityProvider, publicKey keys.PublicKeyBytes) bool {
	return identityProvider.CheckPubKeyPresence(publicKey, identity_provider.RegistrationAdmin)
}

func (tx *TxAccountCreation) Validate(identityProvider *identity_provider.IdentityProvider) bool {
	// TODO: think of a better way to check
	return !identityProvider.CheckPubKeyPresence(tx.NewPublicKey, identity_provider.User) &&
		!identityProvider.CheckPubKeyPresence(tx.NewPublicKey, identity_provider.RegistrationAdmin) &&
		!identityProvider.CheckPubKeyPresence(tx.NewPublicKey, identity_provider.VotingCreationAdmin) &&
		!identityProvider.CheckPubKeyPresence(tx.NewPublicKey, identity_provider.GroupIdentifier)
}
