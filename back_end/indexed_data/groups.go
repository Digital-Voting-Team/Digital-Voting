package indexed_data

import (
	"digital-voting/signature/keys"
	ts "digital-voting/transaction/transaction_specific"
)

type GroupProvider struct {
	IndexedGroups map[[33]byte]ts.TxGroupCreation
}

func NewGroupProvider() *GroupProvider {
	return &GroupProvider{
		IndexedGroups: map[[33]byte]ts.TxGroupCreation{},
	}
}

func (gp *GroupProvider) AddNewGroup(tx ts.TxGroupCreation) {
	identifier := tx.GroupIdentifier
	_, exists := gp.IndexedGroups[identifier]
	if !exists {
		gp.IndexedGroups[identifier] = tx
	}
}

func (gp *GroupProvider) GetTx(identifier [33]byte) ts.TxGroupCreation {
	return gp.IndexedGroups[identifier]
}

func (gp *GroupProvider) RemoveGroup(identifier [33]byte) {
	delete(gp.IndexedGroups, identifier)
}

func (gp *GroupProvider) IsGroupMember(groupIdentifier [33]byte, publicKey keys.PublicKeyBytes) bool {
	// Think of turning into map for better performance
	group, ok := gp.IndexedGroups[groupIdentifier]

	if ok {
		for _, key := range group.MembersPublicKeys {
			if key == publicKey {
				return true
			}
		}
	}

	return false
}
