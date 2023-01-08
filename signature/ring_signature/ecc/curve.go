package ecc

import (
	"errors"
	"fmt"
	"log"
	"math/big"
)

type ICurve interface {
	String() string
	G() *Point
	INF() *Point
	IsOnCurve(P *Point) bool
	AddPoint(P, Q *Point) (*Point, error)
	MulPoint(d *big.Int, P *Point) (*Point, error)
	NegPoint(P *Point) (*Point, error)
	ComputeY(x *big.Int) *big.Int
}

type Point struct {
	X     *big.Int
	Y     *big.Int
	Curve ICurve
}

func (p *Point) IsAtInfinity() bool {
	return p.X == nil && p.Y == nil
}

func (p *Point) String() string {
	return fmt.Sprintf("X = %v, Y = %v", p.X, p.Y)
}

func (p *Point) Eq(other *Point) bool {
	return p.X == other.X && p.X == other.Y
}

func (p *Point) Neg() *Point {
	res, err := p.Curve.NegPoint(p)
	if err != nil {
		log.Fatal(err)
	}
	return res
}

func (p *Point) Add(other *Point) *Point {
	res, err := p.Curve.AddPoint(p, other)
	if err != nil {
		log.Fatal(err)
	}
	return res
}

func (p *Point) Mul(scalar *big.Int) *Point {
	res, err := p.Curve.MulPoint(scalar, p)
	if err != nil {
		log.Fatal(err)
	}
	return res
}

func (p *Point) Copy() *Point {
	return &Point{
		X:     Clone(p.X),
		Y:     Clone(p.Y),
		Curve: p.Curve,
	}
}

type Curve struct {
	Name       string
	A, B, P, N *big.Int
	GX, GY     *big.Int
}

func (c *Curve) String() string {
	return c.Name
}

func (c *Curve) G() *Point {
	return &Point{X: Clone(c.GX), Y: Clone(c.GY), Curve: c}
}

func (c *Curve) INF() *Point {
	return &Point{nil, nil, c}
}

func (c *Curve) IsOnCurve(P *Point) bool {
	if P.Curve.String() != c.Name {
		return false
	}
	return P.IsAtInfinity() || c.isOnCurve(P)
}

func (c *Curve) isOnCurve(P *Point) bool {
	if c.Name == "Curve25519" {
		return c.ConvertToMontgomeryCurve().isOnCurve(P)
	}
	panic("should not be called")
}

func (c *Curve) AddPoint(P, Q *Point) (*Point, error) {
	if (!c.IsOnCurve(P)) || (!c.IsOnCurve(Q)) {
		return &Point{}, errors.New("the points are not on the curve")
	}
	if P.IsAtInfinity() {
		return Q, nil
	}
	if Q.IsAtInfinity() {
		return P, nil
	}

	if P == Q.Neg() {
		return c.INF(), nil
	}
	if P == Q {
		return c.doublePoint(P), nil
	}

	return c.addPoint(P, Q), nil
}

func (c *Curve) addPoint(P, Q *Point) *Point {
	if c.Name == "Curve25519" {
		return c.ConvertToMontgomeryCurve().addPoint(P, Q)
	}
	panic("should not be called")
}

func (c *Curve) doublePoint(P *Point) *Point {
	if c.Name == "Curve25519" {
		return c.ConvertToMontgomeryCurve().doublePoint(P)
	}
	panic("should not be called")
}

func (c *Curve) MulPoint(d *big.Int, P *Point) (*Point, error) {
	if !c.IsOnCurve(P) {
		return &Point{}, errors.New("the point is not on the curve")
	}
	if P.IsAtInfinity() || d.Sign() == 0 {
		return c.INF(), nil
	}

	var err error
	res := c.INF()
	d_ := Clone(d)
	isNegScalar := d_.Sign() < 0
	if isNegScalar {
		d_.Mul(d_, GetInt(-1))
	}
	tmp := P.Copy()

	for d_.Sign() != 0 {
		toCompare := new(big.Int).And(d_, Hex2int("0x1"))
		if toCompare.String() == GetInt(1).String() {
			res, err = c.AddPoint(res, tmp)
			if err != nil {
				return &Point{}, err
			}
		}
		tmp, err = c.AddPoint(tmp, tmp)
		if err != nil {
			return &Point{}, err
		}
		d_.Rsh(d_, 1)
	}
	if isNegScalar {
		return res.Neg(), nil
	}
	return res, nil
}

func (c *Curve) NegPoint(P *Point) (*Point, error) {
	if !c.IsOnCurve(P) {
		return &Point{}, errors.New("the point is not on the curve")
	}
	if P.IsAtInfinity() {
		return c.INF(), nil
	}

	return c.negPoint(P), nil
}

func (c *Curve) negPoint(P *Point) *Point {
	if c.Name == "Curve25519" {
		return c.ConvertToMontgomeryCurve().negPoint(P)
	}
	panic("should not be called")
}

func (c *Curve) ComputeY(x *big.Int) *big.Int {
	if c.Name == "Curve25519" {
		return Clone(c.ConvertToMontgomeryCurve().ComputeY(Clone(x)))
	}
	panic("should not be called")
}

func (c *Curve) ConvertToMontgomeryCurve() *MontgomeryCurve {
	return &MontgomeryCurve{
		*c,
	}
}

// TODO: encode and decode functions

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
	up.Mul(P.X, P.X).Mul(&up, GetInt(3)).Add(&up, new(big.Int).Mul(new(big.Int).Mul(mc.A, P.X), GetInt(2))).Add(&up, GetInt(1))
	down.Mul(GetInt(2), mc.B).Mul(&down, P.Y)
	modInv.ModInverse(&down, mc.P)
	s := new(big.Int).Mul(&up, &modInv) // up * modInv
	// resX := (*mc.B*s*s - *mc.A - 2**P.X) % *mc.P
	// resY := (*P.Y + s*(resX-*P.X)) % *mc.P
	var (
		resX big.Int
		resY big.Int
	)
	resX.Mul(mc.B, s).Mul(&resX, s).Sub(&resX, mc.A).Sub(&resX, new(big.Int).Mul(GetInt(2), P.X)).Mod(&resX, mc.P)
	resY.Sub(&resX, P.X).Mul(&resY, s).Add(&resY, P.Y).Mod(&resY, mc.P)
	return (&Point{&resX, &resY, mc}).Neg()
}

func (mc *MontgomeryCurve) negPoint(P *Point) *Point {
	py := new(big.Int).Mod(new(big.Int).Neg(P.Y), mc.P) // -(*P.Y) % *mc.P
	return &Point{P.X, Clone(py), mc}
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
	return Clone(&y)
}

func NewCurve25519() *MontgomeryCurve {
	a := new(big.Int)
	a.SetInt64(486662)
	b := new(big.Int)
	b.SetInt64(1)
	p := Hex2int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")
	n := Hex2int("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")
	gx := Hex2int("0x9")
	gy := Hex2int("0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9")
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
