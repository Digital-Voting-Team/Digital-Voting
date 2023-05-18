package indexed_data

import (
	"digital-voting/signature/keys"
)

type GroupProvider struct {
	IndexedGroups map[[33]byte]GroupDTO
}

func NewGroupProvider() *GroupProvider {
	return &GroupProvider{
		IndexedGroups: map[[33]byte]GroupDTO{},
	}
}

func (gp *GroupProvider) AddNewGroup(group GroupDTO) {
	identifier := group.GroupIdentifier
	_, exists := gp.IndexedGroups[identifier]
	if !exists {
		gp.IndexedGroups[identifier] = group
	}
}

func (gp *GroupProvider) GetGroup(identifier [33]byte) GroupDTO {
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
