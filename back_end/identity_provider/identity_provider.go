package identity_provider

type IdentityProvider struct {
	UserPubKeys               map[[33]byte]struct{}
	GroupIdentifiers          map[[33]byte]struct{}
	RegistrationAdminPubKeys  map[[33]byte]struct{}
	VotingCreatorAdminPubKeys map[[33]byte]struct{}
	ValidatorPubKeys          map[[33]byte]struct{}
}

type PubKeyType int

const (
	User PubKeyType = iota
	GroupIdentifier
	RegistrationAdmin
	VotingCreationAdmin
	Validator
)

func (ip *IdentityProvider) AddPubKey(publicKey [33]byte, keyType PubKeyType) {
	switch keyType {
	case User:
		_, exists := ip.UserPubKeys[publicKey]
		if !exists {
			ip.UserPubKeys[publicKey] = struct{}{}
		}
	case GroupIdentifier:
		_, exists := ip.GroupIdentifiers[publicKey]
		if !exists {
			ip.GroupIdentifiers[publicKey] = struct{}{}
		}
	case RegistrationAdmin:
		_, exists := ip.RegistrationAdminPubKeys[publicKey]
		if !exists {
			ip.RegistrationAdminPubKeys[publicKey] = struct{}{}
		}
	case VotingCreationAdmin:
		_, exists := ip.VotingCreatorAdminPubKeys[publicKey]
		if !exists {
			ip.VotingCreatorAdminPubKeys[publicKey] = struct{}{}
		}
	case Validator:
		_, exists := ip.ValidatorPubKeys[publicKey]
		if !exists {
			ip.ValidatorPubKeys[publicKey] = struct{}{}
		}
	}
}

func (ip *IdentityProvider) CheckPubKeyPresence(publicKey [33]byte, keyType PubKeyType) bool {
	switch keyType {
	case User:
		_, exists := ip.UserPubKeys[publicKey]
		return exists
	case GroupIdentifier:
		_, exists := ip.GroupIdentifiers[publicKey]
		return exists
	case RegistrationAdmin:
		_, exists := ip.RegistrationAdminPubKeys[publicKey]
		return exists
	case VotingCreationAdmin:
		_, exists := ip.VotingCreatorAdminPubKeys[publicKey]
		return exists
	case Validator:
		_, exists := ip.ValidatorPubKeys[publicKey]
		return exists
	default:
		return false
	}
}

func (ip *IdentityProvider) RemovePubKey(publicKey [33]byte, keyType PubKeyType) {
	switch keyType {
	case User:
		delete(ip.UserPubKeys, publicKey)
	case GroupIdentifier:
		delete(ip.GroupIdentifiers, publicKey)
	case RegistrationAdmin:
		delete(ip.RegistrationAdminPubKeys, publicKey)
	case VotingCreationAdmin:
		delete(ip.VotingCreatorAdminPubKeys, publicKey)
	case Validator:
		delete(ip.ValidatorPubKeys, publicKey)
	}
}
