package main

import (
	"digital-voting/account"
	"digital-voting/block"
	"digital-voting/blockchain"
	ip "digital-voting/identity_provider"
	"digital-voting/signature/keys"
	singleSignature "digital-voting/signature/signatures/single_signature"
	"digital-voting/signer"
	tx "digital-voting/transaction"
	stx "digital-voting/transaction/transaction_specific"
	"digital-voting/validation"
	"fmt"
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

	// Print blockchain
	for _, b := range currentBlockchain.Blocks {
		fmt.Printf("%v\n", b.Header)
	}

}
