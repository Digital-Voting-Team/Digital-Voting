package main

import (
	"digital-voting/account"
	"digital-voting/block"
	"digital-voting/blockchain"
	ip "digital-voting/identity_provider"
	"digital-voting/signature/curve"
	"digital-voting/signature/keys"
	singleSignature "digital-voting/signature/signatures/single_signature"
	"digital-voting/signer"
	tx "digital-voting/transaction"
	stx "digital-voting/transaction/transaction_specific"
	"digital-voting/validation"
	"fmt"
	"time"
)

func main() {
	// Add genesis block
	sign := singleSignature.NewECDSA()
	identityProvider := ip.NewIdentityProvider()

	validatorKeyPair, _ := keys.Random(sign.Curve)
	identityProvider.AddPubKey(validatorKeyPair.PublicToBytes(), ip.Validator)

	validator := &validation.Validator{
		KeyPair:          validatorKeyPair,
		IdentityProvider: identityProvider,
		BlockSigner:      signer.NewBlockSigner(),
	}

	adminKeyPair, _ := keys.Random(sign.Curve)
	identityProvider.AddPubKey(adminKeyPair.PublicToBytes(), ip.RegistrationAdmin)
	identityProvider.AddPubKey(adminKeyPair.PublicToBytes(), ip.VotingCreationAdmin)

	genesisTransaction1 := tx.NewTransaction(tx.AccountCreation, stx.NewTxAccCreation(account.RegistrationAdmin, adminKeyPair.PublicToBytes()))
	genesisTransaction2 := tx.NewTransaction(tx.AccountCreation, stx.NewTxAccCreation(account.VotingCreationAdmin, adminKeyPair.PublicToBytes()))

	txSigner := signer.NewTransactionSigner()
	txSigner.SignTransaction(adminKeyPair, genesisTransaction1)
	txSigner.SignTransaction(adminKeyPair, genesisTransaction2)

	genesisBlock := block.NewBlock([]tx.ITransaction{genesisTransaction1, genesisTransaction2}, [32]byte{})

	validator.SignBlock(genesisBlock)
	currentBlockchain := &blockchain.Blockchain{}
	validator.AddBlockToChain(currentBlockchain, genesisBlock)

	// Add first block with users
	user1 := keys.FromPrivateKey(keys.PrivateKeyBytes{1}, sign.Curve)
	user2 := keys.FromPrivateKey(keys.PrivateKeyBytes{2}, sign.Curve)
	user3 := keys.FromPrivateKey(keys.PrivateKeyBytes{3}, sign.Curve)

	txReg1 := tx.NewTransaction(tx.AccountCreation, stx.NewTxAccCreation(account.User, user1.PublicToBytes()))
	txReg2 := tx.NewTransaction(tx.AccountCreation, stx.NewTxAccCreation(account.User, user2.PublicToBytes()))
	txReg3 := tx.NewTransaction(tx.AccountCreation, stx.NewTxAccCreation(account.User, user3.PublicToBytes()))

	txSigner.SignTransaction(adminKeyPair, txReg1)
	txSigner.SignTransaction(adminKeyPair, txReg2)
	txSigner.SignTransaction(adminKeyPair, txReg3)

	validator.AddToMemPool(txReg1)
	validator.AddToMemPool(txReg2)
	validator.AddToMemPool(txReg3)

	block1 := validator.CreateBlock(genesisBlock.GetHash())
	validator.AddBlockToChain(currentBlockchain, block1)
	validator.ActualizeIdentityProvider(block1)

	// Add second block with voting and group
	whitelist := make([][33]byte, 0, len(identityProvider.UserPubKeys))
	members := make([]keys.PublicKeyBytes, 0, len(identityProvider.UserPubKeys))
	for k := range identityProvider.UserPubKeys {
		whitelist = append(whitelist, k)
		members = append(members, k)
	}

	txVoting := tx.NewTransaction(tx.VotingCreation, stx.NewTxVotingCreation(time.Now(),
		"Black or White?",
		[]string{"Black", "White", "Both"},
		whitelist))
	txGroup := tx.NewTransaction(tx.GroupCreation, stx.NewTxGroupCreation("IPS-41", members...))

	txSigner.SignTransaction(adminKeyPair, txVoting)
	txSigner.SignTransaction(adminKeyPair, txGroup)

	validator.AddToMemPool(txVoting)
	validator.AddToMemPool(txGroup)

	block2 := validator.CreateBlock(block1.GetHash())
	validator.AddBlockToChain(currentBlockchain, block2)
	validator.ActualizeIdentityProvider(block2)

	// Add third block with votings
	txVote1 := tx.NewTransaction(tx.Vote, stx.NewTxVote(txVoting.GetHash(), 1))
	txVote2 := tx.NewTransaction(tx.Vote, stx.NewTxVote(txVoting.GetHash(), 1))
	txVote3 := stx.NewTxVoteAnonymous(txVoting.GetHash(), 2)

	publicKeys := []*curve.Point{user1.GetPublicKey(), user2.GetPublicKey(), user3.GetPublicKey()}

	txSigner.SignTransaction(user1, txVote1)
	txSigner.SignTransaction(user2, txVote2)
	txSigner.SignTransactionAnonymous(user3, publicKeys, 2, txVote3)

	validator.AddToMemPool(txVote1)
	validator.AddToMemPool(txVote2)
	validator.AddToMemPool(txVote3)

	block3 := validator.CreateBlock(block2.GetHash())
	validator.AddBlockToChain(currentBlockchain, block3)
	validator.ActualizeIdentityProvider(block3)

	// Print blockchain
	for _, b := range currentBlockchain.Blocks {
		fmt.Printf("%v\n", b.Header)
	}
}
