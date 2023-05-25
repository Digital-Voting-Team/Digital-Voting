package curve

import (
	"errors"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/signatures/utils"
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
	ComputeDeterministicHash(P *Point) *Point
	MarshalCompressed(point *Point) PointCompressed
	UnmarshalCompressed(data PointCompressed) (point *Point)
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
	return &Point{X: utils.Clone(c.GX), Y: utils.Clone(c.GY), Curve: c}
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
	d_ := utils.Clone(d)
	isNegScalar := d_.Sign() < 0
	if isNegScalar {
		d_.Mul(d_, utils.GetInt(-1))
	}
	tmp := P.Copy()

	for d_.Sign() != 0 {
		toCompare := new(big.Int).And(d_, utils.Hex2int("0x1"))
		if toCompare.String() == utils.GetInt(1).String() {
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
		return utils.Clone(c.ConvertToMontgomeryCurve().ComputeY(utils.Clone(x)))
	}
	panic("should not be called")
}

func (c *Curve) ComputeDeterministicHash(P *Point) *Point {
	if c.Name == "Curve25519" {
		return c.ConvertToMontgomeryCurve().ComputeDeterministicHash(P)
	}
	panic("should not be called")
}

func (c *Curve) MarshalCompressed(point *Point) PointCompressed {
	if c.Name == "Curve25519" {
		return c.ConvertToMontgomeryCurve().MarshalCompressed(point)
	}
	panic("should not be called")
}

func (c *Curve) UnmarshalCompressed(data PointCompressed) (point *Point) {
	if c.Name == "Curve25519" {
		return c.ConvertToMontgomeryCurve().UnmarshalCompressed(data)
	}
	panic("should not be called")
}

func (c *Curve) ConvertToMontgomeryCurve() *MontgomeryCurve {
	return &MontgomeryCurve{
		*c,
	}
}

// TODO: encode and decode functions
