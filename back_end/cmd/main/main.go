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

	genesisTransaction := tx.NewTransaction(tx.AccountCreation, stx.NewTxAccCreation(account.RegistrationAdmin, adminKeyPair.PublicToBytes()))

	txSigner := signer.NewTransactionSigner()
	txSigner.SignTransaction(adminKeyPair, genesisTransaction)

	genesisBlock := block.NewBlock([]tx.ITransaction{genesisTransaction}, [32]byte{})

	validator.SignBlock(genesisBlock)
	currentBlockchain := &blockchain.Blockchain{}
	validator.AddBlockToChain(currentBlockchain, genesisBlock)

	for _, b := range currentBlockchain.Blocks {
		fmt.Printf("%v\n", b)
	}
}
