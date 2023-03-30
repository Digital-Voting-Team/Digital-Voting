package indexed_data

import ts "digital-voting/transaction/transaction_specific"

type VotingProvider struct {
	IndexedVotings map[[32]byte]ts.TxVotingCreation
}

func NewVotingProvider() *VotingProvider {
	return &VotingProvider{
		IndexedVotings: map[[32]byte]ts.TxVotingCreation{},
	}
}

func (vp *VotingProvider) AddNewVoting(tx ts.TxVotingCreation) {
	hash := tx.GetHashInBytes()
	_, exists := vp.IndexedVotings[hash]
	if !exists {
		vp.IndexedVotings[hash] = tx
	}
}

func (vp *VotingProvider) GetTx(hash [32]byte) ts.TxVotingCreation {
	return vp.IndexedVotings[hash]
}

func (vp *VotingProvider) RemoveVoting(hash [32]byte) {
	delete(vp.IndexedVotings, hash)
}
