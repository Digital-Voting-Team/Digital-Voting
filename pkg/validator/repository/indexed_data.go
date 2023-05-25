package repository

import (
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository/account_manager"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository/indexed_groups"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository/indexed_votings"
	"sync"
)

// IndexedData TODO: move functions with Node here instead of elsewhere
type IndexedData struct {
	AccountManager *account_manager.AccountManager
	GroupManager   *indexed_groups.GroupManager
	VotingManager  *indexed_votings.VotingManager
	Mutex          sync.Mutex
}

func NewIndexedData() *IndexedData {
	return &IndexedData{
		AccountManager: account_manager.NewAccountManager(),
		GroupManager:   indexed_groups.NewGroupManager(),
		VotingManager:  indexed_votings.NewVotingManager(),
	}
}
