package main

import (
	"crypto/sha256"
	"digital-voting/block"
	"digital-voting/blockchain"
	ip "digital-voting/identity_provider"
	"digital-voting/merkle_tree"
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
	sign := singleSignature.NewECDSA()
	identityProvider := ip.NewIdentityProvider()

	validatorKeyPair, _ := keys.FromRawSeed(sha256.Sum256([]byte(time.Now().String())), sign.Curve)
	identityProvider.AddPubKey(validatorKeyPair.PublicToBytes(), ip.Validator)

	validator := &validation.Validator{
		KeyPair:          validatorKeyPair,
		IdentityProvider: identityProvider,
		BlockSigner:      signer.NewBlockSigner(),
	}

	adminKeyPair, _ := keys.FromRawSeed(sha256.Sum256([]byte(time.Now().String())), sign.Curve)
	identityProvider.AddPubKey(adminKeyPair.PublicToBytes(), ip.VotingCreationAdmin)

	genesisTransaction := tx.NewTransaction(0, stx.NewTxAccCreation(0, adminKeyPair.PublicToBytes()))

	txSigner := signer.NewTransactionSigner()
	txSigner.SignTransaction(adminKeyPair, genesisTransaction)

	blockBody := block.Body{
		Transactions: []tx.ITransaction{genesisTransaction},
	}

	blockHeader := block.Header{
		Previous:   [32]byte{},
		TimeStamp:  uint64(time.Now().Unix()),
		MerkleRoot: merkle_tree.GetMerkleRoot(blockBody.Transactions),
	}

	genesisBlock := &block.Block{
		Header: blockHeader,
		Body:   blockBody,
	}

	validator.SignBlock(genesisBlock)
	blockchain := &blockchain.Blockchain{}
	validator.AddBlockToChain(blockchain, genesisBlock)

	for _, block := range blockchain.Blocks {
		fmt.Printf("%v\n", block)
	}
}
