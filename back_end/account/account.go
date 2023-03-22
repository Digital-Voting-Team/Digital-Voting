package account

type Type uint8

const (
	User Type = iota
	RegistrationAdmin
	VotingCreationAdmin
)

type Account struct {
	Type      Type     `json:"type"`
	PublicKey [33]byte `json:"public_key"`
}
