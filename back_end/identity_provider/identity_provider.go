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
	User PubKeyType = iota
	GroupIdentifier
	RegistrationAdmin
	VotingCreatorAdmin
	Validator
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
	case User:
		if !contains(ip.UserPubKeys, publicKey) {
			ip.UserPubKeys = append(ip.UserPubKeys, publicKey)
		}
	case GroupIdentifier:
		if !contains(ip.GroupIdentifiers, publicKey) {
			ip.GroupIdentifiers = append(ip.GroupIdentifiers, publicKey)
		}
	case RegistrationAdmin:
		if !contains(ip.RegistrationAdminPubKeys, publicKey) {
			ip.RegistrationAdminPubKeys = append(ip.RegistrationAdminPubKeys, publicKey)
		}
	case VotingCreatorAdmin:
		if !contains(ip.VotingCreatorAdminPubKeys, publicKey) {
			ip.VotingCreatorAdminPubKeys = append(ip.VotingCreatorAdminPubKeys, publicKey)
		}
	case Validator:
		if !contains(ip.ValidatorPubKeys, publicKey) {
			ip.ValidatorPubKeys = append(ip.ValidatorPubKeys, publicKey)
		}
	}
}

func (ip *IdentityProvider) CheckPubKeyPresence(publicKey [33]byte, keyType PubKeyType) bool {
	switch keyType {
	case User:
		return contains(ip.UserPubKeys, publicKey)
	case GroupIdentifier:
		return contains(ip.GroupIdentifiers, publicKey)
	case RegistrationAdmin:
		return contains(ip.RegistrationAdminPubKeys, publicKey)
	case VotingCreatorAdmin:
		return contains(ip.VotingCreatorAdminPubKeys, publicKey)
	case Validator:
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
	case User:
		remove(ip.UserPubKeys, publicKey)
	case GroupIdentifier:
		remove(ip.GroupIdentifiers, publicKey)
	case RegistrationAdmin:
		remove(ip.RegistrationAdminPubKeys, publicKey)
	case VotingCreatorAdmin:
		remove(ip.VotingCreatorAdminPubKeys, publicKey)
	case Validator:
		remove(ip.ValidatorPubKeys, publicKey)
	}
}
