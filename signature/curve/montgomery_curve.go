package curve

import (
	"digital-voting/signature/signatures/utils"
	"math/big"
)

// MontgomeryCurve
// by^2 = x^3 + ax^2 + x
// https://en.wikipedia.org/wiki/Montgomery_curve
type MontgomeryCurve struct {
	Curve
}

func (mc *MontgomeryCurve) isOnCurve(P *Point) bool {
	var (
		left  big.Int
		right big.Int
		res   big.Int
	)
	left.Mul(P.Y, P.Y).Mul(&left, mc.B)
	right.Mul(P.X, P.X).Mul(&right, P.X).Add(&right, new(big.Int).Mul(new(big.Int).Mul(mc.A, P.X), P.X)).Add(&right, P.X)
	res.Sub(&left, &right).Mod(&res, mc.P)
	return res.Sign() == 0
}

func (mc *MontgomeryCurve) addPoint(P, Q *Point) *Point {
	// s = (yP - yQ) / (xP - xQ)
	// xR = b * s^2 - a - xP - xQ
	// yR = yP + s * (xR - xP)
	deltaX := new(big.Int).Sub(P.X, Q.X) // *P.X - *Q.X

	deltaY := new(big.Int).Sub(P.Y, Q.Y) // *P.Y - *Q.Y
	// modInv, err := Modinv(deltaX, *mc.P)
	modInv := new(big.Int).ModInverse(deltaX, mc.P)

	s := new(big.Int).Mul(deltaY, modInv) // deltaY * modInv
	// resX := (*mc.B*s*s - *mc.A - *P.X - *Q.X) % *mc.P
	// resY := (*P.Y + s*(resX-*P.X)) % *mc.P
	var (
		resX big.Int
		resY big.Int
	)
	resX.Mul(mc.B, s).Mul(&resX, s).Sub(&resX, mc.A).Sub(&resX, P.X).Sub(&resX, Q.X).Mod(&resX, mc.P)
	resY.Sub(&resX, P.X).Mul(&resY, s).Add(&resY, P.Y).Mod(&resY, mc.P)
	return (&Point{&resX, &resY, mc}).Neg()
}

func (mc *MontgomeryCurve) doublePoint(P *Point) *Point {
	// s = (3 * xP^2 + 2 * a * xP + 1) / (2 * b * yP)
	// xR = b * s^2 - a - 2 * xP
	// yR = yP + s * (xR - xP)
	// up := 3**P.X**P.X + 2**mc.A**P.X + 1
	// down := 2 * *mc.B * *P.Y
	// modInv, err := Modinv(down, *mc.P)
	var (
		up     big.Int
		down   big.Int
		modInv big.Int
	)
	up.Mul(P.X, P.X).Mul(&up, utils.GetInt(3)).Add(&up, new(big.Int).Mul(new(big.Int).Mul(mc.A, P.X), utils.GetInt(2))).Add(&up, utils.GetInt(1))
	down.Mul(utils.GetInt(2), mc.B).Mul(&down, P.Y)
	modInv.ModInverse(&down, mc.P)
	s := new(big.Int).Mul(&up, &modInv) // up * modInv
	// resX := (*mc.B*s*s - *mc.A - 2**P.X) % *mc.P
	// resY := (*P.Y + s*(resX-*P.X)) % *mc.P
	var (
		resX big.Int
		resY big.Int
	)
	resX.Mul(mc.B, s).Mul(&resX, s).Sub(&resX, mc.A).Sub(&resX, new(big.Int).Mul(utils.GetInt(2), P.X)).Mod(&resX, mc.P)
	resY.Sub(&resX, P.X).Mul(&resY, s).Add(&resY, P.Y).Mod(&resY, mc.P)
	return (&Point{&resX, &resY, mc}).Neg()
}

func (mc *MontgomeryCurve) negPoint(P *Point) *Point {
	py := new(big.Int).Mod(new(big.Int).Neg(P.Y), mc.P) // -(*P.Y) % *mc.P
	return &Point{P.X, utils.Clone(py), mc}
}

func (mc *MontgomeryCurve) ComputeY(x *big.Int) *big.Int {
	// right := (x*x*x + *mc.A*x*x + x) % *mc.P
	// invB, err := Modinv(*mc.B, *mc.P)
	// right = (right * invB) % *mc.P
	// y := Modsqrt(right, *mc.P)
	var (
		right big.Int
		invB  big.Int
		y     big.Int
	)
	right.Mul(x, x).Mul(&right, x).Add(&right, new(big.Int).Mul(new(big.Int).Mul(mc.A, x), x)).Add(&right, x).Mod(&right, mc.P)
	invB.ModInverse(mc.B, mc.P)
	right.Mul(&right, &invB).Mod(&right, mc.P)
	y.ModSqrt(&right, mc.P)
	return utils.Clone(&y)
}

func (mc *MontgomeryCurve) ComputeDeterministicHash(P *Point) *Point {
	publicKeyInteger := new(big.Int).Set(new(big.Int).Add(P.X, P.Y))
	publicKeyInteger.Mod(publicKeyInteger, mc.P)
	return mc.G().Mul(publicKeyInteger)
}

func NewCurve25519() *MontgomeryCurve {
	a := new(big.Int)
	a.SetInt64(486662)
	b := new(big.Int)
	b.SetInt64(1)
	p := utils.Hex2int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")
	n := utils.Hex2int("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")
	gx := utils.Hex2int("0x9")
	gy := utils.Hex2int("0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9")
	return &MontgomeryCurve{
		Curve{
			Name: "Curve25519",
			A:    a,
			B:    b,
			P:    p,
			N:    n,
			GX:   gx,
			GY:   gy,
		},
	}
}

func (mc *MontgomeryCurve) MarshalCompressed(point *Point) [33]byte {
	// TODO: think of different lengths
	compressed := [33]byte{}
	compressed[0] = byte(point.Y.Bit(0)) | 2
	point.X.FillBytes(compressed[1:])
	return compressed
}

func (mc *MontgomeryCurve) UnmarshalCompressed(data [33]byte) (point *Point) {
	// TODO: think of different lengths
	result := &Point{nil, nil, mc}

	x := new(big.Int).SetBytes(data[1:])

	y := mc.ComputeY(x)

	if byte(y.Bit(0)) != data[0]&1 {
		y.Neg(y).Mod(y, mc.P)
	}

	result.X = x
	result.Y = y
	return result
}
