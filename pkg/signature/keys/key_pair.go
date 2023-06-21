package keys

import (
	"bytes"
	"encoding/hex"
	curve2 "github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/curve"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/signatures/utils"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/strkey"
	"io"
	"log"
	"math/big"
)

type PrivateKeyBytes [32]byte
type PublicKeyBytes [33]byte

type KeyPair struct {
	address    string
	seed       string
	privateKey *big.Int
	publicKey  *curve2.Point
	curve      curve2.ICurve
}

func (kp *KeyPair) SetPrivateKey(privateKey *big.Int) {
	kp.privateKey = privateKey
}

func (kp *KeyPair) SetPublicKey(publicKey *curve2.Point) {
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
	kp.publicKey = kp.curve.UnmarshalCompressed(curve2.PointCompressed(data))
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
func (kp *KeyPair) GetPublicKey() *curve2.Point {
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

func newKeyPair(seed string, curve curve2.ICurve) (*KeyPair, error) {
	rawSeed, err := strkey.Decode(strkey.VersionByteSeed, seed)
	if err != nil {
		return nil, err
	}

	reader := bytes.NewReader(rawSeed)
	private := genPrivateKey(reader)
	public := getPublicKey(private, curve)

	publicBytes := public.X.Bytes()
	address, err := strkey.Encode(strkey.VersionBytePublicKey, publicBytes)
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

func newKeyPairFromRawSeed(rawSeed [32]byte, curve curve2.ICurve) (*KeyPair, error) {
	seed, err := strkey.Encode(strkey.VersionByteSeed, rawSeed[:])
	if err != nil {
		return nil, err
	}

	reader := bytes.NewReader(rawSeed[:])
	private := genPrivateKey(reader)
	public := getPublicKey(private, curve)

	publicBytes := public.X.Bytes()
	address, err := strkey.Encode(strkey.VersionBytePublicKey, publicBytes)
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

func newKeyPairFromPrivateKey(privateKeyBytes PrivateKeyBytes, curve curve2.ICurve) *KeyPair {
	private := new(big.Int).SetBytes(privateKeyBytes[:])
	public := getPublicKey(private, curve)
	return &KeyPair{
		privateKey: private,
		publicKey:  public,
		curve:      curve,
	}
}

func genPrivateKey(reader io.Reader) *big.Int {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(reader, seed); err != nil {
		log.Fatal(err)
	}

	return utils.Hex2int(hex.EncodeToString(seed))
}

func getPublicKey(d *big.Int, curve curve2.ICurve) *curve2.Point {
	return curve.G().Mul(d)
}

func (kp *KeyPair) GetKeyImage() *curve2.Point {
	pKey := new(big.Int).Set(kp.privateKey)

	keyImage, err := kp.curve.MulPoint(pKey, kp.curve.ComputeDeterministicHash(kp.publicKey))
	if err != nil {
		log.Panicln(err)
	}

	return keyImage
}
