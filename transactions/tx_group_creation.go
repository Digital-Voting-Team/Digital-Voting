package transactions

import (
	"encoding/json"
	"fmt"
)

type TxGroupCreation struct {
	GroupIdentifier   [33]byte   `json:"group_identifier"`
	GroupName         [256]byte  `json:"group_name"`
	MembersPublicKeys [][33]byte `json:"members_public_keys"`
	AdminSignature    Signature  `json:"admin_signature"`
	AdminPubKey       [33]byte   `json:"admin_pub_key"`
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

func (tx *TxGroupCreation) String() string {
	str, _ := json.Marshal(tx)
	return string(str)
}
