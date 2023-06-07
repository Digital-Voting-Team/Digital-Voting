package indexed_votings

type VotingDTO struct {
	Hash              [32]byte    `json:"hash"`
	ExpirationDate    uint32      `json:"expiration_date"`
	VotingDescription [1024]byte  `json:"voting_description"`
	Answers           [][256]byte `json:"answers"`
	// Not a keys.PublicKeyBytes since it can be group identifier as well
	Whitelist map[[33]byte]struct{} `json:"whitelist"`
}

func NewVotingDTO(hash [32]byte, expirationDate uint32, votingDescription [1024]byte, answers [][256]byte, whitelist [][33]byte) *VotingDTO {
	wl := make(map[[33]byte]struct{})
	for _, pubKey := range whitelist {
		wl[pubKey] = struct{}{}
	}

	return &VotingDTO{
		Hash:              hash,
		ExpirationDate:    expirationDate,
		VotingDescription: votingDescription,
		Answers:           answers,
		Whitelist:         wl,
	}
}
