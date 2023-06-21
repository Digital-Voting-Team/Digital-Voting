package signer

import (
	tx "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction"
	ts "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction/transaction_specific"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/curve"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
	rs "github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/signatures/ring_signature"
	ss "github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/signatures/single_signature"
	"log"
)

type TransactionSigner struct {
	TxSigner          *ss.ECDSA
	TxSignerAnonymous *rs.ECDSA_RS
}

func NewTransactionSigner() *TransactionSigner {
	return &TransactionSigner{TxSigner: ss.NewECDSA(), TxSignerAnonymous: rs.NewECDSA_RS()}
}

func (ts *TransactionSigner) SignTransaction(keyPair *keys.KeyPair, transaction *tx.Transaction) {
	privateKey := keyPair.GetPrivateKey()
	publicKey := keyPair.GetPublicKey()
	messageToSign := transaction.GetSignatureMessage()

	edwardsSignature := ts.TxSigner.SignEdDSA(messageToSign, privateKey, publicKey)
	signature := ts.TxSigner.EdwardsToSingleSignature(edwardsSignature)
	transaction.Sign(keyPair.PublicToBytes(), signature.EdwardsSignatureToBytes())
}

func (ts *TransactionSigner) SignTransactionAnonymous(keyPair *keys.KeyPair, publicKeys []*curve.Point, s int, transaction *ts.TxVoteAnonymous) {
	messageToSign := transaction.GetSignatureMessage()

	rSignature, err := ts.TxSignerAnonymous.Sign(messageToSign, keyPair, publicKeys, s)
	if err != nil {
		log.Panicln(err)
	}

	pKeysData := make([]keys.PublicKeyBytes, len(publicKeys))
	for i := 0; i < len(pKeysData); i++ {
		pKeysData[i] = keys.PublicKeyBytes(publicKeys[i].PointToBytes())
	}

	rSigData, keyImage := rSignature.SignatureToBytes()
	transaction.Sign(pKeysData, rSigData, keyImage)
}

func (ts *TransactionSigner) SignTransactionWithPrivateKey(privateKey keys.PrivateKeyBytes, transaction *tx.Transaction) {
	keyPair := keys.FromPrivateKey(privateKey, curve.NewCurve25519())
	ts.SignTransaction(keyPair, transaction)
}

func (ts *TransactionSigner) SignTransactionAnonymousWithPrivateKey(privateKey keys.PrivateKeyBytes, publicKeys []keys.PublicKeyBytes, s int, transaction *ts.TxVoteAnonymous) {
	keyPair := keys.FromPrivateKey(privateKey, curve.NewCurve25519())
	messageToSign := transaction.GetSignatureMessage()
	signature, err := ts.TxSignerAnonymous.SignBytes(
		messageToSign,
		keyPair.PrivateToBytes(),
		keyPair.PublicToBytes(),
		publicKeys,
		s,
	)
	if err != nil {
		log.Panicln(err)
	}

	rSigData, keyImage := signature.SignatureToBytes()
	transaction.Sign(publicKeys, rSigData, keyImage)
}
