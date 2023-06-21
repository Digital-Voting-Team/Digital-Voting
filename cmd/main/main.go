package main

import (
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/block"
	tx "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/curve"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/connections/web_socket/network_node"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository/account_manager"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository/indexed_votings"
)

func main() {
	channels := validator.Communication{
		NetworkToValidator: make(chan *block.Block),
		ValidatorToNetwork: make(chan *block.Block),
		BlockResponse:      make(chan validator.ResponseMessage),
		BlockApproval:      make(chan *block.Block),
		ApprovalResponse:   make(chan bool),
		BlockDenial:        make(chan *block.Block),
		Transaction:        make(chan tx.ITransaction),
		TxResponse:         make(chan bool),
		ValidatorKeys:      make(chan []keys.PublicKeyBytes),
		Votings:            make(chan []indexed_votings.VotingDTO),
		PublicKey:          make(chan keys.PublicKeyBytes),
	}

	bc := &blockchain.Blockchain{}
	_ = bc.AddBlock(&block.Block{})

	v := validator.NewValidator(
		bc,
		channels,
	)

	nn := network_node.NewNetworkNode(
		"localhost:8081",
		v.KeyPair.PublicToBytes(),
		channels,
	)

	keyPair := keys.FromPrivateKey(keys.PrivateKeyBytes{1}, curve.NewCurve25519())
	v.IndexedData.AccountManager.AddPubKey(keyPair.PublicToBytes(), account_manager.RegistrationAdmin)
	v.IndexedData.AccountManager.AddPubKey(keyPair.PublicToBytes(), account_manager.VotingCreationAdmin)
	v.IndexedData.AccountManager.AddPubKey(keyPair.PublicToBytes(), account_manager.User)

	_ = nn.Start(":8080")
}
