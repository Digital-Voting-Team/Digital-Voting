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
	netToValChan := make(chan *block.Block)
	valToNetChan := make(chan *block.Block)
	blockApprovalChan := make(chan *block.Block)
	approveResponseChan := make(chan bool)
	blockDenialChan := make(chan *block.Block)
	transactionChan := make(chan tx.ITransaction)
	blockResponseChan := make(chan validator.ResponseMessage)
	txResponseChan := make(chan bool)
	validatorKeysChan := make(chan []keys.PublicKeyBytes)
	votingsChan := make(chan []indexed_votings.VotingDTO)
	pubKeyChan := make(chan keys.PublicKeyBytes)
	bc := &blockchain.Blockchain{}
	_ = bc.AddBlock(&block.Block{})

	v := validator.NewValidator(
		bc,
		netToValChan,
		valToNetChan,
		blockApprovalChan,
		approveResponseChan,
		blockDenialChan,
		transactionChan,
		txResponseChan,
		blockResponseChan,
		validatorKeysChan,
		votingsChan,
		pubKeyChan,
	)
	pubKey := v.KeyPair.PublicToBytes()

	nn := network_node.NewNetworkNode(
		"localhost:8081",
		valToNetChan,
		netToValChan,
		blockApprovalChan,
		approveResponseChan,
		blockResponseChan,
		validatorKeysChan,
		transactionChan,
		txResponseChan,
		votingsChan,
		pubKeyChan,
		pubKey,
	)

	keyPair := keys.FromPrivateKey(keys.PrivateKeyBytes{1}, curve.NewCurve25519())
	v.IndexedData.AccountManager.AddPubKey(keyPair.PublicToBytes(), account_manager.RegistrationAdmin)
	v.IndexedData.AccountManager.AddPubKey(keyPair.PublicToBytes(), account_manager.VotingCreationAdmin)
	v.IndexedData.AccountManager.AddPubKey(keyPair.PublicToBytes(), account_manager.User)

	_ = nn.Start(":8080")
}
