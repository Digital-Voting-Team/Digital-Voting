package keys

import (
	"crypto/rand"
	"digital-voting/curve"
	"digital-voting/strkey"
	"errors"
	"io"
	"math/big"
)

var (
	// ErrInvalidKey will be returned by operations when the keys being used
	// could not be decoded.
	ErrInvalidKey = errors.New("invalid key")

	//// ErrInvalidSignature is returned when the signature is invalid, either
	//// through malformation or if it does not verify the message against the
	//// provided public key
	//ErrInvalidSignature = errors.New("signature verification failed")
	//
	//// ErrCannotSign is returned when attempting to sign a message when
	//// the keys do not have the secret key available
	//ErrCannotSign = errors.New("cannot sign")
)

// KP is the main interface for this package
type KP interface {
	Address() string
	FromAddress() (*FromAddress, error)
	Hint() [4]byte
	GetPrivateKey() *big.Int
	GetPublicKey() *curve.Point
	GetKeyImage() *curve.Point
}

// Random creates a random KeyPair keys
func Random() (*KeyPair, error) {
	var rawSeed [32]byte

	_, err := io.ReadFull(rand.Reader, rawSeed[:])
	if err != nil {
		return nil, err
	}

	kp, err := FromRawSeed(rawSeed)
	if err != nil {
		return nil, err
	}

	return kp, nil
}

// Parse constructs a new KP from the provided string, which should be either
// an address, or a seed. If the provided input is a seed, the resulting KP
// will have signing capabilities.
func Parse(addressOrSeed string, curve curve.ICurve) (KP, error) {
	addr, err := ParseAddress(addressOrSeed)
	if err == nil {
		return addr, nil
	}

	if err != strkey.ErrInvalidVersionByte {
		return nil, err
	}

	return ParseKeyPair(addressOrSeed, curve)
}

// ParseAddress constructs a new FromAddress keys from the provided string,
// which should be an address.
func ParseAddress(address string) (*FromAddress, error) {
	return newFromAddress(address)
}

// ParseKeyPair constructs a new KeyPair keys from the provided string, which should
// be a seed.
func ParseKeyPair(seed string, curve curve.ICurve) (*KeyPair, error) {
	return newKeyPair(seed, curve)
}

// FromRawSeed creates a new keys from the provided raw ED25519 seed
func FromRawSeed(rawSeed [32]byte) (*KeyPair, error) {
	curve := curve.NewCurve25519()
	return newKeyPairFromRawSeed(rawSeed, curve)
}
