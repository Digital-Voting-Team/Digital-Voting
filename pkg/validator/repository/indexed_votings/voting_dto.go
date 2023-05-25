package indexed_votings

type VotingDTO struct {
	Hash              [32]byte
	ExpirationDate    uint32
	VotingDescription [1024]byte
	Answers           [][256]byte
	// Not a keys.PublicKeyBytes since it can be group identifier as well
	Whitelist [][33]byte
}
