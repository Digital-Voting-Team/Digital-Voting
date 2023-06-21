package signatures

import (
	crypto "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	crv "github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/curve"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/signatures/utils"
	"log"
	"math/big"
	"math/rand"
	"time"
)

type ECDSA struct {
	GenPoint *crv.Point
	Curve    *crv.MontgomeryCurve
}

func NewECDSA() *ECDSA {
	curve := crv.NewCurve25519()
	return &ECDSA{
		GenPoint: curve.G(),
		Curve:    curve,
	}
}

type SingleSignature struct {
	R *big.Int `json:"r"`
	S *big.Int `json:"s"`
}

type EdwardsSignature struct {
	R *crv.Point
	S *big.Int
}

type SingleSignatureBytes [65]byte

func (ss *SingleSignature) SignatureToBytes() SingleSignatureBytes {
	result := SingleSignatureBytes{}
	result[0] = '0'
	ss.R.FillBytes(result[1:33])
	ss.S.FillBytes(result[33:])

	return result
}

func BytesToSignature(data SingleSignatureBytes) *SingleSignature {
	//version := data[0]
	rInt := new(big.Int).SetBytes(data[1:33])
	sInt := new(big.Int).SetBytes(data[33:])
	return &SingleSignature{R: rInt, S: sInt}
}

func (ec *ECDSA) SignBytes(message string, privateKey keys.PrivateKeyBytes) *SingleSignature {
	keyPair := new(keys.KeyPair)
	keyPair.BytesToPrivate(privateKey)

	return ec.Sign(message, keyPair.GetPrivateKey())
}

func (ec *ECDSA) Sign(message string, privateKey *big.Int) *SingleSignature {
	rand.Seed(time.Now().UnixNano())
	var (
		r     big.Int
		s     big.Int
		randK *big.Int
	)
	for s.String() == "0" {
		for r.String() == "0" {
			randK, _ = crypto.Int(crypto.Reader, new(big.Int).Sub(ec.Curve.N, utils.GetInt(1)))

			kG, err := ec.Curve.MulPoint(utils.Clone(randK), ec.GenPoint)
			if err != nil {
				log.Fatal(err)
			}

			r.Mod(kG.X, ec.Curve.N) // *kG.X % *ec.Curve.N
		}

		invK := new(big.Int).ModInverse(randK, ec.Curve.N)

		h := sha256.New()
		h.Write([]byte(message))
		e := utils.Hex2int(hex.EncodeToString(h.Sum(nil)))

		s.Mul(privateKey, &r).Add(&s, e).Mul(&s, invK).Mod(&s, ec.Curve.N)
	}
	return &SingleSignature{R: &r, S: &s}
}

func (ec *ECDSA) EdwardsToSingleSignature(edwards *EdwardsSignature) *SingleSignature {
	bytes := ec.Curve.MarshalCompressed(edwards.R)
	return &SingleSignature{
		R: new(big.Int).SetBytes(bytes[:]),
		S: edwards.S,
	}
}

func (ec *ECDSA) SingleToEdwardsSignature(single *SingleSignature) *EdwardsSignature {
	bytes := crv.PointCompressed{}
	single.R.FillBytes(bytes[:])
	return &EdwardsSignature{
		R: ec.Curve.UnmarshalCompressed(bytes),
		S: single.S,
	}
}

func (ec *ECDSA) SignEdDSA(message string, privateKey *big.Int, publicKey *crv.Point) *EdwardsSignature {
	rand.Seed(65)
	var (
		R   *crv.Point
		s   big.Int
		err error
	)
	for s.String() == "0" {
		h := sha256.New()
		h.Write(privateKey.Bytes())
		h.Write([]byte(message))
		r := utils.Hex2int(hex.EncodeToString(h.Sum(nil)))
		r.Mod(r, ec.Curve.N)

		R, err = ec.Curve.MulPoint(utils.Clone(r), ec.GenPoint)
		if err != nil {
			log.Fatal(err)
		}

		h = sha256.New()
		h.Write([]byte(R.String() + publicKey.String() + message))
		H := utils.Hex2int(hex.EncodeToString(h.Sum(nil)))
		H.Mod(H, ec.Curve.N)

		s.Mul(privateKey, H).Add(&s, r).Mod(&s, ec.Curve.N)
	}
	return &EdwardsSignature{R: R, S: &s}
}

func (ec *ECDSA) VerifyBytes(message string, publicKey keys.PublicKeyBytes, signature SingleSignatureBytes) bool {
	pubKey := crv.BytesToPoint(crv.PointCompressed(publicKey), ec.Curve)
	sig := BytesToSignature(signature)

	return ec.Verify(message, pubKey, sig)
}

func (ec *ECDSA) Verify(message string, publicKey *crv.Point, signature *SingleSignature) bool {
	if !utils.CheckInterval(signature.R, utils.GetInt(1), new(big.Int).Sub(ec.Curve.N, utils.GetInt(1))) ||
		!utils.CheckInterval(signature.S, utils.GetInt(1), new(big.Int).Sub(ec.Curve.N, utils.GetInt(1))) {
		return false
	}

	h := sha256.New()
	h.Write([]byte(message))
	e := utils.Hex2int(hex.EncodeToString(h.Sum(nil)))

	var w big.Int
	w.ModInverse(signature.S, ec.Curve.N)

	var (
		u1 big.Int
		u2 big.Int
	)
	u1.Mul(e, &w).Mod(&u1, ec.Curve.N)
	u2.Mul(signature.R, &w).Mod(&u2, ec.Curve.N)

	u1G, err := ec.Curve.MulPoint(&u1, ec.GenPoint)
	if err != nil {
		log.Fatal(err)
	}
	u2G, err := ec.Curve.MulPoint(&u2, publicKey)
	if err != nil {
		log.Fatal(err)
	}
	pointX, err := ec.Curve.AddPoint(u1G, u2G)
	if err != nil {
		log.Fatal(err)
	}

	if !ec.Curve.IsOnCurve(pointX) {
		return false
	}
	v := new(big.Int).Mod(pointX.X, ec.Curve.N)

	return new(big.Int).Sub(v, signature.R).String() == "0"
}

func (ec *ECDSA) VerifyEdDSA(message string, publicKey *crv.Point, signature *EdwardsSignature) bool {
	if !ec.Curve.IsOnCurve(signature.R) ||
		!utils.CheckInterval(signature.S, utils.GetInt(1), new(big.Int).Sub(ec.Curve.N, utils.GetInt(1))) {
		return false
	}

	h := sha256.New()
	h.Write([]byte(signature.R.String() + publicKey.String() + message))
	H := utils.Hex2int(hex.EncodeToString(h.Sum(nil)))
	H.Mod(H, ec.Curve.N)

	P1, err := ec.Curve.MulPoint(utils.Clone(signature.S), ec.GenPoint)
	if err != nil {
		log.Fatal(err)
	}

	k, err := ec.Curve.MulPoint(H, publicKey)
	P2, err := ec.Curve.AddPoint(signature.R, k)
	if err != nil {
		log.Fatal(err)
	}

	return P1.Eq(P2)
}

func (ed *EdwardsSignature) Eq(other *EdwardsSignature) bool {
	return ed.S.Cmp(other.S) == 0 && ed.R.Eq(other.R)
}
