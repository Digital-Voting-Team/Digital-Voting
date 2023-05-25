package indexed_groups

import (
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
)

type GroupManager struct {
	IndexedGroups map[[33]byte]GroupDTO
}

func NewGroupManager() *GroupManager {
	return &GroupManager{
		IndexedGroups: map[[33]byte]GroupDTO{},
	}
}

func (gp *GroupManager) AddNewGroup(group GroupDTO) {
	identifier := group.GroupIdentifier
	_, exists := gp.IndexedGroups[identifier]
	if !exists {
		gp.IndexedGroups[identifier] = group
	}
}

func (gp *GroupManager) GetGroup(identifier [33]byte) GroupDTO {
	return gp.IndexedGroups[identifier]
}

func (gp *GroupManager) RemoveGroup(identifier [33]byte) {
	delete(gp.IndexedGroups, identifier)
}

func (gp *GroupManager) IsGroupMember(groupIdentifier [33]byte, publicKey keys.PublicKeyBytes) bool {
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
