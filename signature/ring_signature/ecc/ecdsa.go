package ecc

import (
	crypto "crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"log"
	"math/big"
	"math/rand"
	"time"
)

type ECDSA struct {
	GenPoint *Point
	Curve    *MontgomeryCurve
}

func NewECDSA() *ECDSA {
	curve := NewCurve25519()
	return &ECDSA{
		GenPoint: curve.G(),
		Curve:    curve,
	}
}

func (ec *ECDSA) Sign(privateKey *big.Int, message string) (*big.Int, *big.Int) {
	rand.Seed(time.Now().UnixNano())
	var (
		r     big.Int
		s     big.Int
		randK *big.Int
	)
	for s.String() == "0" {
		for r.String() == "0" {
			// 1. Select a random or pseudorandom integer k, 1 ≤ k ≤ n - 1
			randK, _ = crypto.Int(crypto.Reader, new(big.Int).Sub(ec.Curve.N, GetInt(1)))

			// 2. Compute kG = (x1, y1) and convert x1 to an integer x1
			kG, err := ec.Curve.MulPoint(Clone(randK), ec.GenPoint)
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
		e := Hex2int(hex.EncodeToString(h.Sum(nil)))

		// 6. Compute 5 = k-1(ec + dr) mod n. If s = 0 then go to step 1.
		// s = invK * (e + privateKey*r) % *ec.Curve.N
		s.Mul(privateKey, &r).Add(&s, e).Mul(&s, invK).Mod(&s, ec.Curve.N)
	}
	// 7. A's signature for the message m is (r, s).
	return &r, &s
}

func (ec *ECDSA) Verify(publicKey Point, message string, r, s *big.Int) bool {
	// 1. Verify that r and s are integers in the interval [1, n - 1].
	if !CheckInterval(r, GetInt(1), new(big.Int).Sub(ec.Curve.N, GetInt(1))) ||
		!CheckInterval(s, GetInt(1), new(big.Int).Sub(ec.Curve.N, GetInt(1))) {
		return false
	}

	// 2. Compute SHA-1(m) and convert this bit string to an integer e
	h := sha1.New()
	h.Write([]byte(message))
	e := Hex2int(hex.EncodeToString(h.Sum(nil)))

	// 3. Compute w = s^-1 mod n.
	var w big.Int
	w.ModInverse(s, ec.Curve.N)

	// 4. Compute u1 = ew mod n and u2 = rw mod n.
	var (
		u1 big.Int
		u2 big.Int
	)
	u1.Mul(e, &w).Mod(&u1, ec.Curve.N)
	u2.Mul(r, &w).Mod(&u2, ec.Curve.N)

	// 5. Compute X = u1G + u2Q.
	u1G, err := ec.Curve.MulPoint(&u1, ec.GenPoint)
	if err != nil {
		log.Fatal(err)
	}
	u2G, err := ec.Curve.MulPoint(&u2, &publicKey)
	if err != nil {
		log.Fatal(err)
	}
	pointX, err := ec.Curve.AddPoint(u1G, u2G)
	if err != nil {
		log.Fatal(err)
	}

	// 6. If X = 0, then reject the signature.
	// Otherwise, convert the x-coordinate x1 of X to an integer x1, and compute v = x1 mod n.
	if !ec.Curve.IsOnCurve(pointX) {
		return false
	}
	// v := *pointX.X % *ec.Curve.N
	v := new(big.Int).Mod(pointX.X, ec.Curve.N)

	// 7. Accept the signature if and only if v = r.
	return new(big.Int).Sub(v, r).String() == "0"
}
