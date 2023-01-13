package transactions

import "fmt"

type Address string
type Signature string

type txVotingCreation struct {
	txType            uint8
	expirationDate    uint32
	votingDescription [1024]byte
	answers           [][256]byte
	whitelist         [256]Address
	AdminSignature    Signature
	AdminPubKey       Address
	nonce             uint32
}

func newTxVotingCreation(txType uint8, expirationDate uint32, votingDescription [1024]byte, answers [][256]byte, whitelist [256]Address, nonce uint32) *txVotingCreation {
	return &txVotingCreation{txType: txType, expirationDate: expirationDate, votingDescription: votingDescription, answers: answers, whitelist: whitelist, nonce: nonce}
}

func (tx *txVotingCreation) GetStringToSign() string {
	return fmt.Sprintf("%d, %d, %v, %v, %v, %d", tx.txType, tx.expirationDate, tx.votingDescription, tx.answers, tx.whitelist, tx.nonce)
}
