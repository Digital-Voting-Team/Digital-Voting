package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"digital-voting/strkey"
	"filippo.io/edwards25519"
	"strconv"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 64
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 64
	// SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	SeedSize = 32
)

// KeyPair represents a keys with generated on ed25519 key pair and seed
// used for its creation. In addition, it stores address which is
// public key representation in human-readable form.
type KeyPair struct {
	address    string
	seed       string
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

// Seed is seed getter.
func (kp *KeyPair) Seed() string {
	return kp.seed
}

// Address is address getter.
func (kp *KeyPair) Address() string {
	return kp.address
}

// PublicKey is public key getter.
func (kp *KeyPair) PublicKey() ed25519.PublicKey {
	public, _ := kp.keys()

	return public
}

// Hint provides four last bytes of public key.
func (kp *KeyPair) Hint() (r [4]byte) {
	copy(r[:], kp.publicKey[28:])
	return
}

// FromAddress gets the address-only representation, or public key, of this
// KeyPair keys.
func (kp *KeyPair) FromAddress() (*FromAddress, error) {
	return newFromAddress(kp.address)
}

// Verify checks whether message was signed by kp's keys.
func (kp *KeyPair) Verify(message, signature []byte) error {
	if len(signature) != 64 {
		return ErrInvalidSignature
	}
	if !ed25519.Verify(kp.publicKey, message, signature) {
		return ErrInvalidSignature
	}
	return nil
}

// Sign signs message using edwards25519 package.
func (kp *KeyPair) Sign(message []byte) ([]byte, error) {
	signature := make([]byte, SignatureSize)
	sign(signature, kp.privateKey, message)
	return signature, nil
}

func sign(signature, privateKey, message []byte) {
	if l := len(privateKey); l != PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}
	seed, publicKey := privateKey[:SeedSize], privateKey[SeedSize:]

	h := sha512.Sum512(seed)
	s, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}
	prefix := h[32:]

	mh := sha512.New()
	mh.Write(prefix)
	mh.Write(message)
	messageDigest := make([]byte, 0, sha512.Size)
	messageDigest = mh.Sum(messageDigest)
	r, err := edwards25519.NewScalar().SetUniformBytes(messageDigest)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	R := (&edwards25519.Point{}).ScalarBaseMult(r)

	kh := sha512.New()
	kh.Write(R.Bytes())
	kh.Write(publicKey)
	kh.Write(message)
	hramDigest := make([]byte, 0, sha512.Size)
	hramDigest = kh.Sum(hramDigest)
	k, err := edwards25519.NewScalar().SetUniformBytes(hramDigest)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	S := edwards25519.NewScalar().MultiplyAdd(k, s, r)

	copy(signature[:32], R.Bytes())
	copy(signature[32:], S.Bytes())
}

// Equal compares two KeyPair instances.
func (kp *KeyPair) Equal(f *KeyPair) bool {
	if kp == nil && f == nil {
		return true
	}
	if kp == nil || f == nil {
		return false
	}
	return kp.seed == f.seed
}

func newKeyPair(seed string) (*KeyPair, error) {
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
	return &KeyPair{
		address:    address,
		seed:       seed,
		publicKey:  public,
		privateKey: private,
	}, nil
}

func newKeyPairFromRawSeed(rawSeed [32]byte) (*KeyPair, error) {
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
	return &KeyPair{
		address:    address,
		seed:       seed,
		publicKey:  public,
		privateKey: private,
	}, nil
}

func (kp *KeyPair) keys() (publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) {
	reader := bytes.NewReader(kp.rawSeed())
	public, private, err := ed25519.GenerateKey(reader)
	if err != nil {
		panic(err)
	}
	return public, private
}

func (kp *KeyPair) rawSeed() []byte {
	return strkey.MustDecode(strkey.VersionByteSeed, kp.seed)
}
