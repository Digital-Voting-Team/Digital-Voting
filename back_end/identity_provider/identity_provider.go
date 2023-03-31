package identity_provider

import "digital-voting/signature/keys"

// IdentityProvider TODO: change name to Account manager
type IdentityProvider struct {
	UserPubKeys               map[keys.PublicKeyBytes]struct{}
	GroupIdentifiers          map[keys.PublicKeyBytes]struct{}
	RegistrationAdminPubKeys  map[keys.PublicKeyBytes]struct{}
	VotingCreatorAdminPubKeys map[keys.PublicKeyBytes]struct{}
	ValidatorPubKeys          map[keys.PublicKeyBytes]struct{}
}

func NewIdentityProvider() *IdentityProvider {
	return &IdentityProvider{
		UserPubKeys:               map[keys.PublicKeyBytes]struct{}{},
		GroupIdentifiers:          map[keys.PublicKeyBytes]struct{}{},
		RegistrationAdminPubKeys:  map[keys.PublicKeyBytes]struct{}{},
		VotingCreatorAdminPubKeys: map[keys.PublicKeyBytes]struct{}{},
		ValidatorPubKeys:          map[keys.PublicKeyBytes]struct{}{},
	}
}

type Identifier int

const (
	User Identifier = iota
	RegistrationAdmin
	VotingCreationAdmin
	GroupIdentifier
	Validator
)

func (ip *IdentityProvider) AddPubKey(publicKey keys.PublicKeyBytes, keyType Identifier) {
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

func (ip *IdentityProvider) CheckPubKeyPresence(publicKey keys.PublicKeyBytes, keyType Identifier) bool {
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

func (ip *IdentityProvider) RemovePubKey(publicKey keys.PublicKeyBytes, keyType Identifier) {
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
