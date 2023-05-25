package main

import (
	"fmt"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/block"
	transaction2 "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction"
	transaction_specific2 "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction/transaction_specific"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/models/account"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/curve"
	keys2 "github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
	singleSignature "github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/signatures/single_signature"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signer"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator"
	nd "github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository"
	ip "github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository/account_manager"
	"log"
	"time"
)

func main() {
	// Add genesis block
	sign := singleSignature.NewECDSA()
	node := nd.NewIndexedData()

	validatorKeyPair, _ := keys2.Random(sign.Curve)
	node.AccountManager.AddPubKey(validatorKeyPair.PublicToBytes(), ip.Validator)

	validator := &validator.Validator{
		KeyPair:     validatorKeyPair,
		Node:        node,
		BlockSigner: signer.NewBlockSigner(),
	}

	adminKeyPair, _ := keys2.Random(sign.Curve)
	node.AccountManager.AddPubKey(adminKeyPair.PublicToBytes(), ip.RegistrationAdmin)
	node.AccountManager.AddPubKey(adminKeyPair.PublicToBytes(), ip.VotingCreationAdmin)

	genesisTransaction1 := transaction2.NewTransaction(transaction2.AccountCreation, transaction_specific2.NewTxAccCreation(account.RegistrationAdmin, adminKeyPair.PublicToBytes()))
	genesisTransaction2 := transaction2.NewTransaction(transaction2.AccountCreation, transaction_specific2.NewTxAccCreation(account.VotingCreationAdmin, adminKeyPair.PublicToBytes()))

	txSigner := signer.NewTransactionSigner()
	txSigner.SignTransaction(adminKeyPair, genesisTransaction1)
	txSigner.SignTransaction(adminKeyPair, genesisTransaction2)

	genesisBlock := block.NewBlock([]transaction2.ITransaction{genesisTransaction1, genesisTransaction2}, [32]byte{})

	validator.SignAndUpdateBlock(genesisBlock)
	currentBlockchain := &blockchain.Blockchain{}
	validator.Blockchain = currentBlockchain
	err := validator.AddBlockToChain(genesisBlock)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	// Add first block with users
	user1 := keys2.FromPrivateKey(keys2.PrivateKeyBytes{1}, sign.Curve)
	user2 := keys2.FromPrivateKey(keys2.PrivateKeyBytes{2}, sign.Curve)
	user3 := keys2.FromPrivateKey(keys2.PrivateKeyBytes{3}, sign.Curve)

	txReg1 := transaction2.NewTransaction(transaction2.AccountCreation, transaction_specific2.NewTxAccCreation(account.User, user1.PublicToBytes()))
	txReg2 := transaction2.NewTransaction(transaction2.AccountCreation, transaction_specific2.NewTxAccCreation(account.User, user2.PublicToBytes()))
	txReg3 := transaction2.NewTransaction(transaction2.AccountCreation, transaction_specific2.NewTxAccCreation(account.User, user3.PublicToBytes()))

	txSigner.SignTransaction(adminKeyPair, txReg1)
	txSigner.SignTransaction(adminKeyPair, txReg2)
	txSigner.SignTransaction(adminKeyPair, txReg3)

	validator.AddToMemPool(txReg1)
	validator.AddToMemPool(txReg2)
	validator.AddToMemPool(txReg3)

	block1 := validator.CreateBlock(genesisBlock.GetHash())
	validator.AddBlockToChain(block1)
	validator.ActualizeNodeData(block1)

	// Add second block with voting and group
	whitelist := make([][33]byte, 0, len(node.AccountManager.UserPubKeys))
	members := make([]keys2.PublicKeyBytes, 0, len(node.AccountManager.UserPubKeys))
	for k := range node.AccountManager.UserPubKeys {
		whitelist = append(whitelist, k)
		members = append(members, k)
	}

	txVoting := transaction2.NewTransaction(transaction2.VotingCreation, transaction_specific2.NewTxVotingCreation(time.Now(),
		"Black or White?",
		[]string{"Black", "White", "Both"},
		whitelist))
	txGroup := transaction2.NewTransaction(transaction2.GroupCreation, transaction_specific2.NewTxGroupCreation("IPS-41", members))

	txSigner.SignTransaction(adminKeyPair, txVoting)
	txSigner.SignTransaction(adminKeyPair, txGroup)

	validator.AddToMemPool(txVoting)
	validator.AddToMemPool(txGroup)

	block2 := validator.CreateBlock(block1.GetHash())
	validator.AddBlockToChain(block2)
	validator.ActualizeNodeData(block2)

	// Add third block with votings
	txVote1 := transaction2.NewTransaction(transaction2.Vote, transaction_specific2.NewTxVote(txVoting.GetHash(), 1))
	txVote2 := transaction2.NewTransaction(transaction2.Vote, transaction_specific2.NewTxVote(txVoting.GetHash(), 1))
	txVote3 := transaction_specific2.NewTxVoteAnonymous(txVoting.GetHash(), 2)

	publicKeys := []*curve.Point{user1.GetPublicKey(), user2.GetPublicKey(), user3.GetPublicKey()}

	txSigner.SignTransaction(user1, txVote1)
	txSigner.SignTransaction(user2, txVote2)
	txSigner.SignTransactionAnonymous(user3, publicKeys, 2, txVote3)

	validator.AddToMemPool(txVote1)
	validator.AddToMemPool(txVote2)
	validator.AddToMemPool(txVote3)

	block3 := validator.CreateBlock(block2.GetHash())
	err = validator.AddBlockToChain(block3)
	if err != nil {
		log.Panicln(err)
	}
	validator.ActualizeNodeData(block3)

	// Print blockchain
	for _, b := range currentBlockchain.Blocks {
		fmt.Printf("%v\n", b.Header)
	}
}
