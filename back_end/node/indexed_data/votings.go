package indexed_data

type VotingProvider struct {
	IndexedVotings map[[32]byte]VotingDTO
}

func NewVotingProvider() *VotingProvider {
	return &VotingProvider{
		IndexedVotings: map[[32]byte]VotingDTO{},
	}
}

func (vp *VotingProvider) AddNewVoting(voting VotingDTO) {
	hash := voting.Hash
	_, exists := vp.IndexedVotings[hash]
	if !exists {
		vp.IndexedVotings[hash] = voting
	}
}

func (vp *VotingProvider) GetVoting(hash [32]byte) VotingDTO {
	return vp.IndexedVotings[hash]
}

func (vp *VotingProvider) RemoveVoting(hash [32]byte) {
	delete(vp.IndexedVotings, hash)
}
