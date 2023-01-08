package ring_signature

import (
	"crypto/rand"
	"crypto/sha256"
	"digital-voting/signature"
	"fmt"
	"log"
	"math/big"
)

var (
	curve = signature.NewCurve25519()
)

type RingSignature struct {
	KeyImage *signature.Point
	CList    []*big.Int
	RList    []*big.Int
}

func SignMessage(message string, privateKey *big.Int, publicKey *signature.Point, publicKeys []*signature.Point, s int) (*RingSignature, error) {
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
	var lArray []*signature.Point
	var rArray []*signature.Point

	keyImage := signature.GetKeyImage(curve, publicKey, privateKey)

	for i := 0; i < numberOfPKeys; i++ {
		qI := new(big.Int).Set(rList[i])

		qG, err := curve.MulPoint(qI, curve.G())
		if err != nil {
			log.Panicln(err)
		}

		qH, err := curve.MulPoint(qI, curve.ComputeDeterministicHash(publicKeys[i].Copy()))
		if err != nil {
			log.Panicln(err)
		}

		if i == s {
			lArray = append(lArray, qG)
			rArray = append(rArray, qH)
			continue
		}

		wI := new(big.Int).Set(cList[i])

		wP, err := curve.MulPoint(wI, publicKeys[i].Copy())
		if err != nil {
			log.Panicln(err)
		}

		qGwP, err := curve.AddPoint(qG, wP)
		if err != nil {
			log.Panicln(err)
		}

		wIPoint, err := curve.MulPoint(wI, keyImage)
		if err != nil {
			log.Panicln(err)
		}

		qHwI, err := curve.AddPoint(qH, wIPoint)
		if err != nil {
			log.Panicln(err)
		}

		lArray = append(lArray, qGwP)
		rArray = append(rArray, qHwI)
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

func (sig *RingSignature) VerifySignature(message string, publicKeys []*signature.Point) bool {
	numberOfPKeys := len(publicKeys)
	var newLArray []*signature.Point
	var newRArray []*signature.Point

	cExpected := new(big.Int)

	for i := 0; i < numberOfPKeys; i++ {
		rI := new(big.Int).Set(sig.RList[i])

		rG, err := curve.MulPoint(rI, curve.G())
		if err != nil {
			log.Panicln(err)
		}

		rH, err := curve.MulPoint(rI, curve.ComputeDeterministicHash(publicKeys[i].Copy()))
		if err != nil {
			log.Panicln(err)
		}

		cI := new(big.Int).Set(sig.CList[i])

		cP, err := curve.MulPoint(cI, publicKeys[i].Copy())
		if err != nil {
			log.Panicln(err)
		}

		cIPoint, err := curve.MulPoint(cI, sig.KeyImage)
		if err != nil {
			log.Panicln(err)
		}

		currentLValue, err := curve.AddPoint(rG, cP)
		if err != nil {
			log.Panicln(err)
		}

		currentRValue, err := curve.AddPoint(rH, cIPoint)
		if err != nil {
			log.Panicln(err)
		}

		newLArray = append(newLArray, currentLValue)
		newRArray = append(newRArray, currentRValue)

		cExpected = new(big.Int).Mod(new(big.Int).Add(cExpected, sig.CList[i]), curve.N)
	}

	hash := getHash(message, newLArray, newRArray)
	cReal := new(big.Int).Mod(new(big.Int).SetBytes(hash[:]), curve.N)

	return cReal.Cmp(cExpected) == 0
}

func getHash(message string, lArray, rArray []*signature.Point) [32]byte {
	messageToHash := message

	for i := 0; i < len(lArray); i++ {
		messageToHash += fmt.Sprintf("%v", lArray[i])
	}

	for i := 0; i < len(rArray); i++ {
		messageToHash += fmt.Sprintf("%v", rArray[i])
	}

	return sha256.Sum256([]byte(messageToHash))
}
