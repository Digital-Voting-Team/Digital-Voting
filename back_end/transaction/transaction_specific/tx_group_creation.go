package transaction_specific

import (
	"crypto/sha256"
	"digital-voting/identity_provider"
	"fmt"
	"reflect"
)

type TxGroupCreation struct {
	GroupIdentifier   [33]byte   `json:"group_identifier"`
	GroupName         [256]byte  `json:"group_name"`
	MembersPublicKeys [][33]byte `json:"members_public_keys"`
}

func NewTxGroupCreation(groupName string, membersPublicKeys ...[33]byte) *TxGroupCreation {
	grpName := [256]byte{}
	copy(grpName[:], groupName)

	hasher := sha256.New()

	groupIdentifier := []byte(fmt.Sprintf("%v, %v", grpName, membersPublicKeys))
	hasher.Write(groupIdentifier)
	groupIdentifier = hasher.Sum(nil)
	grpId := [33]byte{}
	//version byte
	//grpId[0] = 0
	copy(grpId[1:], groupIdentifier)

	return &TxGroupCreation{GroupIdentifier: grpId, GroupName: grpName, MembersPublicKeys: membersPublicKeys}
}

func (tx *TxGroupCreation) AddGroupMember(publicKey [33]byte) {
	tx.MembersPublicKeys = append(tx.MembersPublicKeys, publicKey)
}

func (tx *TxGroupCreation) RemoveGroupMember(publicKey [33]byte) {
	for i, key := range tx.MembersPublicKeys {
		//it works for [33]byte
		if key == publicKey {
			tx.MembersPublicKeys = append(tx.MembersPublicKeys[:i], tx.MembersPublicKeys[i+1:]...)
			return
		}
	}
}

func (tx *TxGroupCreation) GetSignatureMessage() string {
	return fmt.Sprintf("%v, %v, %v", tx.GroupIdentifier, tx.GroupName, tx.MembersPublicKeys)
}

func (tx *TxGroupCreation) IsEqual(otherTransaction *TxGroupCreation) bool {
	return tx.GroupIdentifier == otherTransaction.GroupIdentifier &&
		tx.GroupName == otherTransaction.GroupName &&
		reflect.DeepEqual(tx.MembersPublicKeys, otherTransaction.MembersPublicKeys)
}

func (tx *TxGroupCreation) CheckPublicKeyByRole(identityProvider *identity_provider.IdentityProvider, publicKey [33]byte) bool {
	return identityProvider.CheckPubKeyPresence(publicKey, identity_provider.RegistrationAdmin)
}

func (tx *TxGroupCreation) Validate(identityProvider *identity_provider.IdentityProvider) bool {
	if identityProvider.CheckPubKeyPresence(tx.GroupIdentifier, identity_provider.GroupIdentifier) {
		return false
	}
	for _, pubKey := range tx.MembersPublicKeys {
		if !identityProvider.CheckPubKeyPresence(pubKey, identity_provider.User) {
			return false
		}
	}
	return true
}
