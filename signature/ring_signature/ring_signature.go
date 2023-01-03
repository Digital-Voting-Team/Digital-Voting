package ring_signature

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"filippo.io/edwards25519"
	"fmt"
	"log"
	"math/big"
)

type RingSignature struct {
	KeyImage *edwards25519.Point
	CList    []*big.Int
	RList    []*big.Int
}

func SignMessage(message string, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, publicKeys []ed25519.PublicKey, s int) (*RingSignature, error) {
	numberOfPKeys := len(publicKeys)

	if s < 0 || s >= numberOfPKeys {
		return nil, fmt.Errorf("wrong index of personal key")
	}

	cList := make([]*big.Int, numberOfPKeys)
	rList := make([]*big.Int, numberOfPKeys)

	//2^252 + 27742317777372353535851937790883648493
	order := big.NewInt(0)
	order.SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

	for i := 0; i < numberOfPKeys; i++ {
		cList[i], _ = rand.Int(rand.Reader, order)
		rList[i], _ = rand.Int(rand.Reader, order)
	}
	var lArray []*edwards25519.Point
	var rArray []*edwards25519.Point

	basePoint := edwards25519.NewGeneratorPoint()

	for i := 0; i < numberOfPKeys; i++ {
		b := rList[i].Bytes()
		appendLength := 32 - len(b)
		b = append(make([]byte, appendLength), b...)
		reverseBytes(b)
		qI, err := edwards25519.NewScalar().SetCanonicalBytes(b)
		if err != nil {
			log.Println(err)
			log.Println(b)
			log.Println(len(b))
		}

		rG := edwards25519.NewGeneratorPoint().ScalarMult(qI, basePoint)
		point, err := edwards25519.NewGeneratorPoint().SetBytes(publicKeys[i])
		if err != nil {
			log.Println(err)
		}
		rH := edwards25519.NewGeneratorPoint().ScalarMult(qI, point)

		if i == s {
			lArray = append(lArray, rG)
			rArray = append(rArray, rH)
			continue
		}

		b = cList[i].Bytes()
		appendLength = 32 - len(b)
		b = append(make([]byte, appendLength), b...)
		reverseBytes(b)
		wI, err := edwards25519.NewScalar().SetCanonicalBytes(b)
		if err != nil {
			log.Println(err)
			log.Println(b)
			log.Println(len(b))
		}

		cP := edwards25519.NewGeneratorPoint().ScalarMult(wI, point)
		rGcP := edwards25519.NewGeneratorPoint().Add(rG, cP)

		//privateKeyScalar := edwards25519.NewScalar().SetCanonicalBytes(privateKey)
		//keyImage := edwards25519.NewGeneratorPoint().ScalarMult()

		cI := edwards25519.NewGeneratorPoint().ScalarMult(wI, point)
		rHcI := edwards25519.NewGeneratorPoint().Add(rH, cI)

		lArray = append(lArray, rGcP)
		rArray = append(rArray, rHcI)
	}

	c := big.NewInt(0)
	hash := getHash(message, lArray, rArray)
	c.SetBytes(hash[:])

	sum := big.NewInt(0)
	for i := 0; i < numberOfPKeys; i++ {
		sum = big.NewInt(0).Add(sum, cList[i])
	}
	cList[s] = big.NewInt(0).Mod(big.NewInt(0).Sub(c, sum), order)

	pKey := big.NewInt(0)
	pKey.SetBytes(privateKey)
	rList[s] = big.NewInt(0).Mod(big.NewInt(0).Sub(rList[s], big.NewInt(0).Mul(cList[s], pKey)), order)

	keyImage, _ := edwards25519.NewGeneratorPoint().SetBytes(publicKey)

	return &RingSignature{
		KeyImage: keyImage,
		CList:    cList,
		RList:    rList,
	}, nil
}

func (sig *RingSignature) VerifySignature(message string, publicKeys []ed25519.PublicKey) bool {
	numberOfPKeys := len(publicKeys)
	var newLArray []*edwards25519.Point
	var newRArray []*edwards25519.Point

	order := big.NewInt(0)
	order.SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

	basePoint := edwards25519.NewGeneratorPoint()
	cExpected := big.NewInt(0)

	for i := 0; i < numberOfPKeys; i++ {
		b := sig.RList[i].Bytes()
		appendLength := 32 - len(b)
		b = append(make([]byte, appendLength), b...)
		reverseBytes(b)
		rI, err := edwards25519.NewScalar().SetCanonicalBytes(b)
		if err != nil {
			log.Println(err)
		}
		rG := edwards25519.NewGeneratorPoint().ScalarMult(rI, basePoint)

		point, err := edwards25519.NewGeneratorPoint().SetBytes(publicKeys[i])
		if err != nil {
			log.Println(err)
		}
		rH := edwards25519.NewGeneratorPoint().ScalarMult(rI, point)

		b = sig.CList[i].Bytes()
		appendLength = 32 - len(b)
		b = append(make([]byte, appendLength), b...)
		reverseBytes(b)
		cI, err := edwards25519.NewScalar().SetCanonicalBytes(b)
		if err != nil {
			log.Println(err)
		}

		cP := edwards25519.NewGeneratorPoint().ScalarMult(cI, point)
		c_I := edwards25519.NewGeneratorPoint().ScalarMult(cI, point)

		currentLValue := edwards25519.NewGeneratorPoint().Add(rG, cP)
		currentRValue := edwards25519.NewGeneratorPoint().Add(rH, c_I)

		newLArray = append(newLArray, currentLValue)
		newRArray = append(newRArray, currentRValue)

		cExpected = big.NewInt(0).Add(cExpected, sig.CList[i])
	}

	cReal := big.NewInt(0)
	hash := getHash(message, newLArray, newRArray)
	cReal.SetBytes(hash[:])
	cReal = big.NewInt(0).Mod(cReal, order)

	return cReal == cExpected
}

func getHash(message string, lArray, rArray []*edwards25519.Point) [32]byte {
	messageToHash := message

	for i := 0; i < len(lArray); i++ {
		messageToHash += fmt.Sprintf("%v", lArray[i])
	}

	for i := 0; i < len(rArray); i++ {
		messageToHash += fmt.Sprintf("%v", rArray[i])
	}

	return sha256.Sum256([]byte(messageToHash))
}

func reverseBytes(bytes []byte) {
	for i := 0; i < len(bytes)/2; i++ {
		bytes[i], bytes[len(bytes)-i-1] = bytes[len(bytes)-i-1], bytes[i]
	}
}
