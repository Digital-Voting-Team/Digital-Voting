package keys

import (
	"bytes"
	"crypto/ed25519"
	"digital-voting/strkey"
)

// Full represents a keys with generated on ed25519 key pair and seed
// used for its creation. In addition, it stores address which is
// public key representation in human-readable form.
type Full struct {
	address    string
	seed       string
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

// Seed is seed getter.
func (kp *Full) Seed() string {
	return kp.seed
}

// Address is address getter.
func (kp *Full) Address() string {
	return kp.address
}

// PublicKey is public key getter.
func (kp *Full) PublicKey() ed25519.PublicKey {
	public, _ := kp.keys()

	return public
}

// Hint provides four last bytes of public key.
func (kp *Full) Hint() (r [4]byte) {
	copy(r[:], kp.publicKey[28:])
	return
}

// FromAddress gets the address-only representation, or public key, of this
// Full keys.
func (kp *Full) FromAddress() (*FromAddress, error) {
	return newFromAddress(kp.address)
}

// Verify checks whether message was signed by kp's keys.
func (kp *Full) Verify(message, signature []byte) error {
	if len(signature) != 64 {
		return ErrInvalidSignature
	}
	if !ed25519.Verify(kp.publicKey, message, signature) {
		return ErrInvalidSignature
	}
	return nil
}

// Sign signs message using ed25519 package.
func (kp *Full) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(kp.privateKey, message), nil
}

// Equal compares two Full instances.
func (kp *Full) Equal(f *Full) bool {
	if kp == nil && f == nil {
		return true
	}
	if kp == nil || f == nil {
		return false
	}
	return kp.seed == f.seed
}

func newFull(seed string) (*Full, error) {
	rawSeed, err := strkey.Decode(strkey.VersionByteSeed, seed)
	if err != nil {
		return nil, err
	}
	reader := bytes.NewReader(rawSeed)
	public, private, err := ed25519.GenerateKey(reader)
	if err != nil {
		return nil, err
	}
	address, err := strkey.Encode(strkey.VersionByteAccountID, public)
	if err != nil {
		return nil, err
	}
	return &Full{
		address:    address,
		seed:       seed,
		publicKey:  public,
		privateKey: private,
	}, nil
}

func newFullFromRawSeed(rawSeed [32]byte) (*Full, error) {
	seed, err := strkey.Encode(strkey.VersionByteSeed, rawSeed[:])
	if err != nil {
		return nil, err
	}
	reader := bytes.NewReader(rawSeed[:])
	public, private, err := ed25519.GenerateKey(reader)
	if err != nil {
		return nil, err
	}
	address, err := strkey.Encode(strkey.VersionByteAccountID, public)
	if err != nil {
		return nil, err
	}
	return &Full{
		address:    address,
		seed:       seed,
		publicKey:  public,
		privateKey: private,
	}, nil
}

func (kp *Full) keys() (publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) {
	reader := bytes.NewReader(kp.rawSeed())
	public, private, err := ed25519.GenerateKey(reader)
	if err != nil {
		panic(err)
	}
	return public, private
}

func (kp *Full) rawSeed() []byte {
	return strkey.MustDecode(strkey.VersionByteSeed, kp.seed)
}
