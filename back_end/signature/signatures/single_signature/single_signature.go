package signatures

import (
	crypto "crypto/rand"
	"crypto/sha1"
	curve2 "digital-voting/signature/curve"
	"digital-voting/signature/signatures/utils"
	"encoding/hex"
	"log"
	"math/big"
	"math/rand"
	"time"
)

type ECDSA struct {
	GenPoint *curve2.Point
	Curve    *curve2.MontgomeryCurve
}

func NewECDSA() *ECDSA {
	curve := curve2.NewCurve25519()
	return &ECDSA{
		GenPoint: curve.G(),
		Curve:    curve,
	}
}

type SingleSignature struct {
	R *big.Int `json:"r"`
	S *big.Int `json:"s"`
}

func (ss *SingleSignature) SignatureToBytes() [65]byte {
	// result[0] -> version
	// result[1:32] -> R
	// result[32:] -> S

	result := [65]byte{}
	result[0] = '0'
	ss.R.FillBytes(result[1:33])
	ss.S.FillBytes(result[33:])

	return result
}

func BytesToSignature(data [65]byte) *SingleSignature {
	//version := data[0]
	rInt := new(big.Int).SetBytes(data[1:33])
	sInt := new(big.Int).SetBytes(data[33:])
	return &SingleSignature{R: rInt, S: sInt}
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
			// 1. Select a random or pseudorandom integer k, 1 ≤ k ≤ n - 1
			randK, _ = crypto.Int(crypto.Reader, new(big.Int).Sub(ec.Curve.N, utils.GetInt(1)))

			// 2. Compute kG = (x1, y1) and convert x1 to an integer x1
			kG, err := ec.Curve.MulPoint(utils.Clone(randK), ec.GenPoint)
			if err != nil {
				log.Fatal(err)
			}
			// 3. Compute r = x1 mod n. If r = 0 then go to step 1.
			r.Mod(kG.X, ec.Curve.N) // *kG.X % *ec.Curve.N
		}

		// 4. Compute k-1 mod n.
		// invK, err := Modinv(randK, *ec.Curve.N)
		invK := new(big.Int).ModInverse(randK, ec.Curve.N)

		// 5. Compute SHA-1(m) and convert this bit string to an integer ec.
		h := sha1.New()
		h.Write([]byte(message))
		e := utils.Hex2int(hex.EncodeToString(h.Sum(nil)))

		// 6. Compute 5 = k-1(ec + dr) mod n. If s = 0 then go to step 1.
		// s = invK * (e + privateKey*r) % *ec.Curve.N
		s.Mul(privateKey, &r).Add(&s, e).Mul(&s, invK).Mod(&s, ec.Curve.N)
	}
	// 7. A's signatures for the message m is (r, s).
	return &SingleSignature{R: &r, S: &s}
}

func (ec *ECDSA) VerifyBytes(message string, publicKey [33]byte, signature [65]byte) bool {
	pubKey := curve2.BytesToPoint(publicKey, ec.Curve)
	sig := BytesToSignature(signature)

	return ec.Verify(message, pubKey, sig)
}

func (ec *ECDSA) Verify(message string, publicKey *curve2.Point, signature *SingleSignature) bool {
	// 1. Verify that r and s are integers in the interval [1, n - 1].
	if !utils.CheckInterval(signature.R, utils.GetInt(1), new(big.Int).Sub(ec.Curve.N, utils.GetInt(1))) ||
		!utils.CheckInterval(signature.S, utils.GetInt(1), new(big.Int).Sub(ec.Curve.N, utils.GetInt(1))) {
		return false
	}

	// 2. Compute SHA-1(m) and convert this bit string to an integer e
	h := sha1.New()
	h.Write([]byte(message))
	e := utils.Hex2int(hex.EncodeToString(h.Sum(nil)))

	// 3. Compute w = s^-1 mod n.
	var w big.Int
	w.ModInverse(signature.S, ec.Curve.N)

	// 4. Compute u1 = ew mod n and u2 = rw mod n.
	var (
		u1 big.Int
		u2 big.Int
	)
	u1.Mul(e, &w).Mod(&u1, ec.Curve.N)
	u2.Mul(signature.R, &w).Mod(&u2, ec.Curve.N)

	// 5. Compute X = u1G + u2Q.
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

	// 6. If X = 0, then reject the signatures.
	// Otherwise, convert the x-coordinate x1 of X to an integer x1, and compute v = x1 mod n.
	if !ec.Curve.IsOnCurve(pointX) {
		return false
	}
	// v := *pointX.X % *ec.Curve.N
	v := new(big.Int).Mod(pointX.X, ec.Curve.N)

	// 7. Accept the signatures if and only if v = r.
	return new(big.Int).Sub(v, signature.R).String() == "0"
}
