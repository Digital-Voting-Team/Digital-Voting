package indexed_data

import "digital-voting/signature/keys"

type GroupDTO struct {
	GroupIdentifier   [33]byte
	GroupName         [256]byte
	MembersPublicKeys []keys.PublicKeyBytes
}
