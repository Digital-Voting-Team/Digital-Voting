package signer

import (
	"digital-voting/signature/curve"
	"digital-voting/signature/keys"
	ringSignature "digital-voting/signature/signatures/ring_signature"
	singleSignature "digital-voting/signature/signatures/single_signature"
	"digital-voting/transaction"
	"digital-voting/transaction/transaction_specific"
	"log"
)

type TransactionSigner struct {
	TxSigner          *singleSignature.ECDSA
	TxSignerAnonymous *ringSignature.ECDSA_RS
}

func NewTransactionSigner() *TransactionSigner {
	return &TransactionSigner{TxSigner: singleSignature.NewECDSA(), TxSignerAnonymous: ringSignature.NewECDSA_RS()}
}

func (ts *TransactionSigner) SignTransaction(keyPair *keys.KeyPair, transaction *transaction.Transaction) {
	privateKey := keyPair.GetPrivateKey()
	messageToSign := transaction.GetSignatureMessage()

	signature := ts.TxSigner.Sign(messageToSign, privateKey)
	transaction.Sign(keyPair.PublicToBytes(), signature.SignatureToBytes())
}

func (ts *TransactionSigner) SignTransactionAnonymous(keyPair *keys.KeyPair, publicKeys []*curve.Point, s int, transaction *transaction_specific.TxVoteAnonymous) {
	messageToSign := transaction.GetSignatureMessage()

	rSignature, err := ts.TxSignerAnonymous.Sign(messageToSign, keyPair, publicKeys, s)
	if err != nil {
		log.Panicln(err)
	}

	pKeysData := make([][33]byte, len(publicKeys))
	for i := 0; i < len(pKeysData); i++ {
		pKeysData[i] = publicKeys[i].PointToBytes()
	}

	rSigData, keyImage := rSignature.SignatureToBytes()
	transaction.Sign(pKeysData, rSigData, keyImage)
}
