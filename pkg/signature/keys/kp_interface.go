package keys

import (
	"crypto/rand"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/curve"
	"io"
	"math/big"
)

// KP is the main interface for this package
type KP interface {
	Address() string
	Hint() [4]byte
	GetPrivateKey() *big.Int
	GetPublicKey() *curve.Point
	GetKeyImage() *curve.Point
}

func FromPrivateKey(privateKeyBytes PrivateKeyBytes, curve curve.ICurve) *KeyPair {
	return newKeyPairFromPrivateKey(privateKeyBytes, curve)
}

// Random creates a random KeyPair keys
func Random(curve curve.ICurve) (*KeyPair, error) {
	var rawSeed [32]byte

	_, err := io.ReadFull(rand.Reader, rawSeed[:])
	if err != nil {
		return nil, err
	}

	kp, err := FromRawSeed(rawSeed, curve)
	if err != nil {
		return nil, err
	}

	return kp, nil
}

// FromRawSeed creates a new keys from the provided raw ED25519 seed
func FromRawSeed(rawSeed [32]byte, curve curve.ICurve) (*KeyPair, error) {
	return newKeyPairFromRawSeed(rawSeed, curve)
}
