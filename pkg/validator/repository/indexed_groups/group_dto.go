package indexed_groups

import (
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
)

type GroupDTO struct {
	GroupIdentifier   [33]byte              `json:"group_identifier"`
	GroupName         [256]byte             `json:"group_name"`
	MembersPublicKeys []keys.PublicKeyBytes `json:"members_public_keys"`
}
