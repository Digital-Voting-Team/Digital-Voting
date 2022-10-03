package group_creation

import "math/rand"

type signature interface {
}

type txGroupCreation struct {
	txType            uint8
	groupIdentifier   [33]byte
	groupName         [256]byte
	membersPublicKeys [][33]byte
	adminSignature    signature
	adminPubKey       [33]byte
	nonce             uint32
}

func newTxGroupCreation(txType uint8, groupIdentifier [33]byte, groupName [256]byte, membersPublicKeys ...[33]byte) *txGroupCreation {
	return &txGroupCreation{txType: txType, groupIdentifier: groupIdentifier, groupName: groupName, membersPublicKeys: membersPublicKeys, nonce: rand.Uint32()}
}

func (tx *txGroupCreation) AddGroupMember(publicKey [33]byte) {
	tx.membersPublicKeys = append(tx.membersPublicKeys, publicKey)
}

func (tx *txGroupCreation) RemoveGroupMember(publicKey [33]byte) {
	for i, key := range tx.membersPublicKeys {
		//it works for [33]byte
		if key == publicKey {
			tx.membersPublicKeys = append(tx.membersPublicKeys[:i], tx.membersPublicKeys[i+1:]...)
			return
		}
	}
}
