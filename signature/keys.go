package signature

import (
	"crypto/rand"
	"digital-voting/signature/utils"
	"encoding/hex"
	"io"
	"log"
	"math/big"
)

func GetKeyPair(curve *MontgomeryCurve) (*big.Int, *Point) {
	pKey := genPrivateKey()
	pubKey := getPublicKey(utils.Clone(pKey), curve)
	return pKey, pubKey
}

func genPrivateKey() *big.Int {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		log.Fatal(err)
	}

	return utils.Hex2int(hex.EncodeToString(seed))
}

func getPublicKey(d *big.Int, curve *MontgomeryCurve) *Point {
	return curve.G().Mul(d)
}

func GetKeyImage(curve *MontgomeryCurve, publicKey *Point, privateKey *big.Int) *Point {
	pKey := new(big.Int).Set(privateKey)

	keyImage, err := curve.MulPoint(pKey, curve.ComputeDeterministicHash(publicKey))
	if err != nil {
		log.Panicln(err)
	}

	return keyImage
}
