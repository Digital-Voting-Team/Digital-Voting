package main

import (
	"digital-voting/block"
	"digital-voting/blockchain"
	"digital-voting/network_node"
	"digital-voting/signature/keys"
	tx "digital-voting/transaction"
	"digital-voting/validation"
)

func main() {
	netToValChan := make(chan *block.Block)
	valToNetChan := make(chan *block.Block)
	blockApprovalChan := make(chan *block.Block)
	blockDenialChan := make(chan *block.Block)
	transactionChan := make(chan tx.ITransaction)
	acceptanceChan := make(chan validation.ResponseMessage)
	validatorKeysChan := make(chan []keys.PublicKeyBytes)
	bc := &blockchain.Blockchain{}
	_ = bc.AddBlock(&block.Block{})

	v := validation.NewValidator(
		bc,
		netToValChan,
		valToNetChan,
		blockApprovalChan,
		blockDenialChan,
		transactionChan,
		acceptanceChan,
		validatorKeysChan,
	)
	pubKey := v.KeyPair.PublicToBytes()

	port := "8083"
	nn := network_node.NewNetworkNode(
		"localhost:"+port,
		valToNetChan,
		netToValChan,
		blockApprovalChan,
		acceptanceChan,
		validatorKeysChan,
		pubKey,
	)
	println("Starting network node on port " + port + "...")
	err := nn.Start(port, "localhost:8081")
	if err != nil {
		return
	}
}
