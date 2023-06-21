package indexed_votings

type VotingManager struct {
	IndexedVotings map[[32]byte]VotingDTO
}

func NewVotingManager() *VotingManager {
	return &VotingManager{
		IndexedVotings: map[[32]byte]VotingDTO{},
	}
}

func (vp *VotingManager) AddNewVoting(voting VotingDTO) {
	hash := voting.Hash
	_, exists := vp.IndexedVotings[hash]
	if !exists {
		vp.IndexedVotings[hash] = voting
	}
}

func (vp *VotingManager) GetVoting(hash [32]byte) VotingDTO {
	return vp.IndexedVotings[hash]
}

func (vp *VotingManager) RemoveVoting(hash [32]byte) {
	delete(vp.IndexedVotings, hash)
}
