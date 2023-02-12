package transactions

import (
	"fmt"
)

type TxGroupCreation struct {
	GroupIdentifier   [33]byte
	GroupName         [256]byte
	MembersPublicKeys [][33]byte
	AdminSignature    Signature
	AdminPubKey       [33]byte
}

func newTxGroupCreation(txType uint8, GroupIdentifier [33]byte, GroupName [256]byte, MembersPublicKeys ...[33]byte) *TxGroupCreation {
	return &TxGroupCreation{GroupIdentifier: GroupIdentifier, GroupName: GroupName, MembersPublicKeys: MembersPublicKeys}
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

func (tx *TxGroupCreation) GetStringToSign() string {
	return fmt.Sprintf("%v, %v, %v", tx.GroupIdentifier, tx.GroupName, tx.MembersPublicKeys)
}
