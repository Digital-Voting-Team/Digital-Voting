package main

import (
	"digital-voting/signature/ring_signature/ecc"

	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
)

var (
	curve = ecc.NewCurve25519()
)

type RingSignature struct {
	KeyImage *ecc.Point
	CList    []*big.Int
	RList    []*big.Int
}

func SignMessage(message string, privateKey *big.Int, publicKey *ecc.Point, publicKeys []*ecc.Point, s int) (*RingSignature, error) {
	numberOfPKeys := len(publicKeys)

	if s < 0 || s >= numberOfPKeys {
		return nil, fmt.Errorf("wrong index of personal key")
	}

	cList := make([]*big.Int, numberOfPKeys)
	rList := make([]*big.Int, numberOfPKeys)

	var err error
	for i := 0; i < numberOfPKeys; i++ {
		cList[i], err = rand.Int(rand.Reader, curve.N)
		if err != nil {
			log.Panicln(err)
		}
		rList[i], err = rand.Int(rand.Reader, curve.N)
		if err != nil {
			log.Panicln(err)
		}
	}
	var lArray []*ecc.Point
	var rArray []*ecc.Point

	keyImage := getKeyImage(publicKey, privateKey)

	for i := 0; i < numberOfPKeys; i++ {
		qI := new(big.Int).Set(rList[i])

		rG, err := curve.MulPoint(qI, curve.G())
		if err != nil {
			log.Panicln(err)
		}

		rH, err := curve.MulPoint(qI, publicKeys[i].Copy())
		if err != nil {
			log.Panicln(err)
		}

		if i == s {
			lArray = append(lArray, rG)
			rArray = append(rArray, rH)
			continue
		}

		wI := new(big.Int).Set(cList[i])

		cP, err := curve.MulPoint(wI, publicKeys[i].Copy())
		if err != nil {
			log.Panicln(err)
		}

		rGcP, err := curve.AddPoint(rG, cP)
		if err != nil {
			log.Panicln(err)
		}

		cI, err := curve.MulPoint(wI, keyImage)
		if err != nil {
			log.Panicln(err)
		}

		rHcI, err := curve.AddPoint(rH, cI)
		if err != nil {
			log.Panicln(err)
		}

		lArray = append(lArray, rGcP)
		rArray = append(rArray, rHcI)
	}

	hash := getHash(message, lArray, rArray)
	c := new(big.Int).SetBytes(hash[:])

	sum := new(big.Int)
	for i := 0; i < numberOfPKeys; i++ {
		if i != s {
			sum = new(big.Int).Add(sum, cList[i])
		}
	}

	pKey := new(big.Int).Set(privateKey)

	cList[s] = new(big.Int).Mod(new(big.Int).Sub(c, sum), curve.N)
	rList[s] = new(big.Int).Mod(new(big.Int).Sub(rList[s], new(big.Int).Mul(cList[s], pKey)), curve.N)

	return &RingSignature{
		KeyImage: keyImage,
		CList:    cList,
		RList:    rList,
	}, nil
}

func getKeyImage(publicKey *ecc.Point, privateKey *big.Int) *ecc.Point {
	pKey := new(big.Int).Set(privateKey)

	keyImage, err := curve.MulPoint(pKey, publicKey)
	if err != nil {
		log.Panicln(err)
	}

	return keyImage
}

func (sig *RingSignature) VerifySignature(message string, publicKeys []*ecc.Point) bool {
	numberOfPKeys := len(publicKeys)
	var newLArray []*ecc.Point
	var newRArray []*ecc.Point

	cExpected := new(big.Int)

	for i := 0; i < numberOfPKeys; i++ {
		rI := new(big.Int).Set(sig.RList[i])

		rG, err := curve.MulPoint(rI, curve.G())
		if err != nil {
			log.Panicln(err)
		}

		rH, err := curve.MulPoint(rI, publicKeys[i].Copy())
		if err != nil {
			log.Panicln(err)
		}

		cI := new(big.Int).Set(sig.CList[i])

		cP, err := curve.MulPoint(cI, publicKeys[i].Copy())
		if err != nil {
			log.Panicln(err)
		}

		c_I, err := curve.MulPoint(cI, sig.KeyImage)
		if err != nil {
			log.Panicln(err)
		}

		currentLValue, err := curve.AddPoint(rG, cP)
		if err != nil {
			log.Panicln(err)
		}

		currentRValue, err := curve.AddPoint(rH, c_I)
		if err != nil {
			log.Panicln(err)
		}

		newLArray = append(newLArray, currentLValue)
		newRArray = append(newRArray, currentRValue)

		cExpected = new(big.Int).Add(cExpected, sig.CList[i])
		cExpected = new(big.Int).Mod(cExpected, curve.N)
	}

	hash := getHash(message, newLArray, newRArray)
	cReal := new(big.Int).SetBytes(hash[:])
	cReal = new(big.Int).Mod(cReal, curve.N)

	return cReal.Cmp(cExpected) == 0
}

func getHash(message string, lArray, rArray []*ecc.Point) [32]byte {
	messageToHash := message

	for i := 0; i < len(lArray); i++ {
		messageToHash += fmt.Sprintf("%v", lArray[i])
	}

	for i := 0; i < len(rArray); i++ {
		messageToHash += fmt.Sprintf("%v", rArray[i])
	}

	return sha256.Sum256([]byte(messageToHash))
}
