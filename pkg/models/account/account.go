package account

import (
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
)

type Type uint8

const (
	User Type = iota
	RegistrationAdmin
	VotingCreationAdmin
)

type Account struct {
	Type      Type                `json:"type"`
	PublicKey keys.PublicKeyBytes `json:"public_key"`
}
