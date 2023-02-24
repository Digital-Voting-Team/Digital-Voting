package signer

import (
	"digital-voting/signature/curve"
	"digital-voting/signature/keys"
	ringSignature "digital-voting/signature/signatures/ring_signature"
	singleSignature "digital-voting/signature/signatures/single_signature"
	"digital-voting/transactions"
	"log"
)

type TransactionSigner struct {
	TxSigner          *singleSignature.ECDSA
	TxSignerAnonymous *ringSignature.ECDSA_RS
}

func NewTransactionSigner() *TransactionSigner {
	return &TransactionSigner{TxSigner: singleSignature.NewECDSA(), TxSignerAnonymous: ringSignature.NewECDSA_RS()}
}

func (ts *TransactionSigner) SignTransaction(keyPair *keys.KeyPair, transaction *transactions.Transaction) {
	privateKey := keyPair.GetPrivateKey()
	messageToSign := transaction.GetStringToSign()

	signature := ts.TxSigner.Sign(privateKey, messageToSign)
	transaction.Signature = *signature
	transaction.PublicKey = *keyPair.GetPublicKey()
}

func (ts *TransactionSigner) SignTransactionAnonymous(keyPair *keys.KeyPair, publicKeys []*curve.Point, s int, transaction *transactions.TxVoteAnonymous) {
	messageToSign := transaction.GetStringToSign()

	rSignature, err := ts.TxSignerAnonymous.Sign(messageToSign, keyPair, publicKeys, s)
	if err != nil {
		log.Panicln(err)
	}

	transaction.RingSignature = *rSignature
}
