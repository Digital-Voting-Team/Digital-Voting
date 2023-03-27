package keys

import (
	"bytes"
	"digital-voting/signature/curve"
	"digital-voting/signature/signatures/utils"
	"digital-voting/signature/strkey"
	"encoding/hex"
	"io"
	"log"
	"math/big"
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

type PrivateKeyBytes [32]byte
type PublicKeyBytes [33]byte

// KeyPair represents a keys with generated on ed25519 key pair and seed
// used for its creation. In addition, it stores address which is
// public key representation in human-readable form.
type KeyPair struct {
	address    string
	seed       string
	privateKey *big.Int
	publicKey  *curve.Point
	curve      curve.ICurve
}

func (kp *KeyPair) SetPrivateKey(privateKey *big.Int) {
	kp.privateKey = privateKey
}

func (kp *KeyPair) SetPublicKey(publicKey *curve.Point) {
	kp.publicKey = publicKey
}

func (kp *KeyPair) BytesToPrivate(privateKey PrivateKeyBytes) {
	kp.privateKey = new(big.Int).SetBytes(privateKey[:])
}

func (kp *KeyPair) PrivateToBytes() PrivateKeyBytes {
	result := PrivateKeyBytes{}
	kp.privateKey.FillBytes(result[:])

	return result
}

func (kp *KeyPair) PublicToBytes() PublicKeyBytes {
	if kp.publicKey == nil {
		panic("not existing public key")
	}

	return PublicKeyBytes(kp.curve.MarshalCompressed(kp.publicKey))
}

func (kp *KeyPair) BytesToPublic(data PublicKeyBytes) {
	kp.publicKey = kp.curve.UnmarshalCompressed(curve.PointCompressed(data))
}

// Seed is seed getter.
func (kp *KeyPair) Seed() string {
	return kp.seed
}

// Address is address getter.
func (kp *KeyPair) Address() string {
	return kp.address
}

// GetPrivateKey is public key getter.
func (kp *KeyPair) GetPrivateKey() *big.Int {
	return kp.privateKey
}

// GetPublicKey is public key getter.
func (kp *KeyPair) GetPublicKey() *curve.Point {
	return kp.publicKey
}

// Hint provides four last bytes of public key.
func (kp *KeyPair) Hint() (r [4]byte) {
	xBytes := kp.publicKey.X.Bytes()
	yBytes := kp.publicKey.Y.Bytes()
	publicBytes := append(xBytes, yBytes...)
	copy(r[:], publicBytes[28:])
	return
}

// FromAddress gets the address-only representation, or public key, of this
// KeyPair keys.
func (kp *KeyPair) FromAddress() (*FromAddress, error) {
	return newFromAddress(kp.address)
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

func newKeyPair(seed string, curve curve.ICurve) (*KeyPair, error) {
	rawSeed, err := strkey.Decode(strkey.VersionByteSeed, seed)
	if err != nil {
		return nil, err
	}

	reader := bytes.NewReader(rawSeed)
	private := genPrivateKey(reader)
	public := getPublicKey(private, curve)

	publicBytes := public.X.Bytes()
	// TODO think about better way to fill address
	//xBytes := public.X.Bytes()
	//yBytes := public.Y.Bytes()
	//publicBytes := append(xBytes, yBytes...)
	address, err := strkey.Encode(strkey.VersionByteAccountID, publicBytes)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		address:    address,
		seed:       seed,
		publicKey:  public,
		privateKey: private,
		curve:      curve,
	}, nil
}

func newKeyPairFromRawSeed(rawSeed [32]byte, curve curve.ICurve) (*KeyPair, error) {
	seed, err := strkey.Encode(strkey.VersionByteSeed, rawSeed[:])
	if err != nil {
		return nil, err
	}

	reader := bytes.NewReader(rawSeed[:])
	private := genPrivateKey(reader)
	public := getPublicKey(private, curve)

	publicBytes := public.X.Bytes()
	// TODO think about better way to fill address
	//xBytes := public.X.Bytes()
	//yBytes := public.Y.Bytes()
	//publicBytes := append(xBytes, yBytes...)
	address, err := strkey.Encode(strkey.VersionByteAccountID, publicBytes)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		address:    address,
		seed:       seed,
		publicKey:  public,
		privateKey: private,
		curve:      curve,
	}, nil
}

func genPrivateKey(reader io.Reader) *big.Int {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(reader, seed); err != nil {
		log.Fatal(err)
	}

	return utils.Hex2int(hex.EncodeToString(seed))
}

func getPublicKey(d *big.Int, curve curve.ICurve) *curve.Point {
	return curve.G().Mul(d)
}

func (kp *KeyPair) GetKeyImage() *curve.Point {
	pKey := new(big.Int).Set(kp.privateKey)

	keyImage, err := kp.curve.MulPoint(pKey, kp.curve.ComputeDeterministicHash(kp.publicKey))
	if err != nil {
		log.Panicln(err)
	}

	return keyImage
}

func (kp *KeyPair) rawSeed() []byte {
	return strkey.MustDecode(strkey.VersionByteSeed, kp.seed)
}
