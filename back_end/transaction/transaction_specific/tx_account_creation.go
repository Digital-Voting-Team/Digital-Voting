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

func (tx *TxAccountCreation) GetHashString() string {
	hash := tx.GetHash()

	return base64.URLEncoding.EncodeToString(hash[:])
}

func (tx *TxAccountCreation) GetHash() [32]byte {
	hasher := sha256.New()

	bytes := []byte(tx.GetSignatureMessage())
	hasher.Write(bytes)
	bytes = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(bytes)

	hash := [32]byte{}
	copy(hash[:], hasher.Sum(nil)[:32])

	return hash
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

func (tx *TxAccountCreation) ActualizeIdentities(identityProvider *identity_provider.IdentityProvider) {
	// TODO: think of linkage between enum in account and in identity provider
	identityProvider.AddPubKey(tx.NewPublicKey, identity_provider.Identifier(tx.AccountType))
}
