package ecc

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"math/big"
)

func GetKeyPair(curve *MontgomeryCurve) (*big.Int, *Point) {
	pKey := genPrivateKey()
	pubKey := getPublicKey(Clone(pKey), curve)
	return pKey, pubKey
}

func genPrivateKey() *big.Int {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		log.Fatal(err)
	}

	return Hex2int(hex.EncodeToString(seed))
}

func getPublicKey(d *big.Int, curve *MontgomeryCurve) *Point {
	return curve.G().Mul(d)
}
