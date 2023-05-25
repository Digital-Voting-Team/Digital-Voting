package node

import (
	"digital-voting/node/account_manager"
	indexed_data2 "digital-voting/node/indexed_data"
	"sync"
)

type Node struct {
	AccountManager *account_manager.AccountManager
	GroupProvider  *indexed_data2.GroupProvider
	VotingProvider *indexed_data2.VotingProvider
	Mutex          sync.Mutex
}

func NewNode() *Node {
	return &Node{
		AccountManager: account_manager.NewAccountManager(),
		GroupProvider:  indexed_data2.NewGroupProvider(),
		VotingProvider: indexed_data2.NewVotingProvider(),
	}
}
