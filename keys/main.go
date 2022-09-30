package keys

import (
	"crypto/rand"
	"digital-voting/strkey"
	"errors"
	"io"
)

var (
	// ErrInvalidKey will be returned by operations when the keys being used
	// could not be decoded.
	ErrInvalidKey = errors.New("invalid key")

	// ErrInvalidSignature is returned when the signature is invalid, either
	// through malformation or if it does not verify the message against the
	// provided public key
	ErrInvalidSignature = errors.New("signature verification failed")

	// ErrCannotSign is returned when attempting to sign a message when
	// the keys do not have the secret key available
	ErrCannotSign = errors.New("cannot sign")
)

// KP is the main interface for this package
type KP interface {
	Address() string
	FromAddress() (*FromAddress, error)
	Hint() [4]byte
	Verify(input []byte, signature []byte) error
	Sign(input []byte) ([]byte, error)
}

// Random creates a random Full keys
func Random() (*Full, error) {
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
func Parse(addressOrSeed string) (KP, error) {
	addr, err := ParseAddress(addressOrSeed)
	if err == nil {
		return addr, nil
	}

	if err != strkey.ErrInvalidVersionByte {
		return nil, err
	}

	return ParseFull(addressOrSeed)
}

// ParseAddress constructs a new FromAddress keys from the provided string,
// which should be an address.
func ParseAddress(address string) (*FromAddress, error) {
	return newFromAddress(address)
}

// ParseFull constructs a new Full keys from the provided string, which should
// be a seed.
func ParseFull(seed string) (*Full, error) {
	return newFull(seed)
}

// FromRawSeed creates a new keys from the provided raw ED25519 seed
func FromRawSeed(rawSeed [32]byte) (*Full, error) {
	return newFullFromRawSeed(rawSeed)
}
