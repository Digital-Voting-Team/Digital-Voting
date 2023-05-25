package signer

import (
	"digital-voting/block"
	"digital-voting/signature/keys"
	singleSignature "digital-voting/signature/signatures/single_signature"
)

type BlockSigner struct {
	BlkSigner *singleSignature.ECDSA
}

func NewBlockSigner() *BlockSigner {
	return &BlockSigner{BlkSigner: singleSignature.NewECDSA()}
}

func (bs *BlockSigner) SignBlock(keyPair *keys.KeyPair, block *block.Block) (keys.PublicKeyBytes, singleSignature.SingleSignatureBytes) {
	privateKey := keyPair.GetPrivateKey()
	publicKey := keyPair.GetPublicKey()
	messageToSign := block.GetHashString()

	signature := bs.BlkSigner.Sign(messageToSign, privateKey)
	return keys.PublicKeyBytes(publicKey.PointToBytes()), signature.SignatureToBytes()
}

func (bs *BlockSigner) SignAndUpdateBlock(keyPair *keys.KeyPair, block *block.Block) {
	block.Sign(bs.SignBlock(keyPair, block))
}
