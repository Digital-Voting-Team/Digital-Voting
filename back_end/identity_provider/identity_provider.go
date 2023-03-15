package identity_provider

type IdentityProvider struct {
	UserPubKeys               [][33]byte
	GroupIdentifiers          [][33]byte
	RegistrationAdminPubKeys  [][33]byte
	VotingCreatorAdminPubKeys [][33]byte
	ValidatorPubKeys          [][33]byte
}

type PubKeyType int

const (
	USER PubKeyType = iota
	GROUP_IDENTIFIER
	REGISTRATION_ADMIN
	VOTING_CREATOR_ADMIN
	VALIDATOR
)

func contains(l [][33]byte, item [33]byte) bool {
	for _, a := range l {
		if a == item {
			return true
		}
	}
	return false
}

func (ip *IdentityProvider) AddPubKey(publicKey [33]byte, keyType PubKeyType) {
	switch keyType {
	case USER:
		if !contains(ip.UserPubKeys, publicKey) {
			ip.UserPubKeys = append(ip.UserPubKeys, publicKey)
		}
	case GROUP_IDENTIFIER:
		if !contains(ip.GroupIdentifiers, publicKey) {
			ip.GroupIdentifiers = append(ip.GroupIdentifiers, publicKey)
		}
	case REGISTRATION_ADMIN:
		if !contains(ip.RegistrationAdminPubKeys, publicKey) {
			ip.RegistrationAdminPubKeys = append(ip.RegistrationAdminPubKeys, publicKey)
		}
	case VOTING_CREATOR_ADMIN:
		if !contains(ip.VotingCreatorAdminPubKeys, publicKey) {
			ip.VotingCreatorAdminPubKeys = append(ip.VotingCreatorAdminPubKeys, publicKey)
		}
	case VALIDATOR:
		if !contains(ip.ValidatorPubKeys, publicKey) {
			ip.ValidatorPubKeys = append(ip.ValidatorPubKeys, publicKey)
		}
	}
}

func (ip *IdentityProvider) CheckPubKeyPresence(publicKey [33]byte, keyType PubKeyType) bool {
	switch keyType {
	case USER:
		return contains(ip.UserPubKeys, publicKey)
	case GROUP_IDENTIFIER:
		return contains(ip.GroupIdentifiers, publicKey)
	case REGISTRATION_ADMIN:
		return contains(ip.RegistrationAdminPubKeys, publicKey)
	case VOTING_CREATOR_ADMIN:
		return contains(ip.VotingCreatorAdminPubKeys, publicKey)
	case VALIDATOR:
		return contains(ip.ValidatorPubKeys, publicKey)
	default:
		return false
	}
}

func remove(l [][33]byte, item [33]byte) [][33]byte {
	for i, other := range l {
		if other == item {
			return append(l[:i], l[i+1:]...)
		}
	}
	return l
}

func (ip *IdentityProvider) RemovePubKey(publicKey [33]byte, keyType PubKeyType) {
	switch keyType {
	case USER:
		remove(ip.UserPubKeys, publicKey)
	case GROUP_IDENTIFIER:
		remove(ip.GroupIdentifiers, publicKey)
	case REGISTRATION_ADMIN:
		remove(ip.RegistrationAdminPubKeys, publicKey)
	case VOTING_CREATOR_ADMIN:
		remove(ip.VotingCreatorAdminPubKeys, publicKey)
	case VALIDATOR:
		remove(ip.ValidatorPubKeys, publicKey)
	}
}
