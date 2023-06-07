package indexed_votings

type VotingDTO struct {
	Hash              [32]byte    `json:"hash"`
	ExpirationDate    uint32      `json:"expiration_date"`
	VotingDescription [1024]byte  `json:"voting_description"`
	Answers           [][256]byte `json:"answers"`
	// Not a keys.PublicKeyBytes since it can be group identifier as well
	Whitelist map[[33]byte]interface{} `json:"whitelist"`
}
