package curve

import (
	"fmt"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/signatures/utils"
	"log"
	"math/big"
)

type PointCompressed [33]byte

type Point struct {
	X     *big.Int
	Y     *big.Int
	Curve ICurve
}

func (p *Point) PointToBytes() PointCompressed {
	return p.Curve.MarshalCompressed(p)
}

func BytesToPoint(data PointCompressed, curve ICurve) *Point {
	return curve.UnmarshalCompressed(data)
}

func (p *Point) IsAtInfinity() bool {
	return p.X == nil && p.Y == nil
}

func (p *Point) String() string {
	return fmt.Sprintf("X = %v, Y = %v", p.X, p.Y)
}

func (p *Point) Eq(other *Point) bool {
	return p.X.Cmp(other.X) == 0 && p.Y.Cmp(other.Y) == 0
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
		X:     utils.Clone(p.X),
		Y:     utils.Clone(p.Y),
		Curve: p.Curve,
	}
}
