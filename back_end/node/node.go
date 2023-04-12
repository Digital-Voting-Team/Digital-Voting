package node

import (
	"digital-voting/account_manager"
	"digital-voting/blockchain"
	"digital-voting/indexed_data"
)

type Node struct {
	Blockchain     *blockchain.Blockchain
	AccountManager *account_manager.AccountManager
	GroupProvider  *indexed_data.GroupProvider
	VotingProvider *indexed_data.VotingProvider
}

func NewNode() *Node {
	return &Node{
		Blockchain:     &blockchain.Blockchain{},
		AccountManager: account_manager.NewAccountManager(),
		GroupProvider:  indexed_data.NewGroupProvider(),
		VotingProvider: indexed_data.NewVotingProvider(),
	}
}
