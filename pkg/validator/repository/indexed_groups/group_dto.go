package indexed_groups

import (
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
)

type GroupDTO struct {
	GroupIdentifier   [33]byte
	GroupName         [256]byte
	MembersPublicKeys []keys.PublicKeyBytes
}
