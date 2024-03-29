package signer

import (
	blk "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/block"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
	ss "github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/signatures/single_signature"
)

type BlockSigner struct {
	BlkSigner *ss.ECDSA
}

func NewBlockSigner() *BlockSigner {
	return &BlockSigner{BlkSigner: ss.NewECDSA()}
}

func (bs *BlockSigner) SignBlock(keyPair *keys.KeyPair, block *blk.Block) (keys.PublicKeyBytes, ss.SingleSignatureBytes) {
	privateKey := keyPair.GetPrivateKey()
	publicKey := keyPair.GetPublicKey()
	messageToSign := block.GetHashString()

	edwardsSignature := bs.BlkSigner.SignEdDSA(messageToSign, privateKey, publicKey)
	signature := bs.BlkSigner.EdwardsToSingleSignature(edwardsSignature)
	return keys.PublicKeyBytes(publicKey.PointToBytes()), signature.EdwardsSignatureToBytes()
}

func (bs *BlockSigner) SignAndUpdateBlock(keyPair *keys.KeyPair, block *blk.Block) {
	block.Sign(bs.SignBlock(keyPair, block))
}
