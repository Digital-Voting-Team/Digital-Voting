package transaction_specific

import (
	"crypto/sha256"
	"digital-voting/account"
	"digital-voting/account_manager"
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

func (tx *TxAccountCreation) CheckPublicKeyByRole(identityProvider *account_manager.AccountManager, publicKey keys.PublicKeyBytes) bool {
	return identityProvider.CheckPubKeyPresence(publicKey, account_manager.RegistrationAdmin)
}

func (tx *TxAccountCreation) Validate(identityProvider *account_manager.AccountManager) bool {
	// TODO: think of a better way to check
	return !identityProvider.CheckPubKeyPresence(tx.NewPublicKey, account_manager.User) &&
		!identityProvider.CheckPubKeyPresence(tx.NewPublicKey, account_manager.RegistrationAdmin) &&
		!identityProvider.CheckPubKeyPresence(tx.NewPublicKey, account_manager.VotingCreationAdmin) &&
		!identityProvider.CheckPubKeyPresence(tx.NewPublicKey, account_manager.GroupIdentifier)
}

func (tx *TxAccountCreation) ActualizeIdentities(identityProvider *account_manager.AccountManager) {
	// TODO: think of linkage between enum in account and in identity provider
	identityProvider.AddPubKey(tx.NewPublicKey, account_manager.Identifier(tx.AccountType))
}
