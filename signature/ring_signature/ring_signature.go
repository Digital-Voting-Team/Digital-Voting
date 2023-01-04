package ring_signature

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"fmt"
	"log"
	"math/big"
)

var (
	order      *big.Int
	fieldOrder *big.Int
	basePoint  *edwards25519.Point
)

func init() {
	//2^252 + 27742317777372353535851937790883648493
	order = big.NewInt(0)
	order.SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

	fieldOrder = big.NewInt(0)
	fieldOrder.SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)

	basePoint = edwards25519.NewGeneratorPoint()
}

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

	for i := 0; i < numberOfPKeys; i++ {
		cList[i], _ = rand.Int(rand.Reader, order)
		rList[i], _ = rand.Int(rand.Reader, order)
	}
	var lArray []*edwards25519.Point
	var rArray []*edwards25519.Point

	keyImage := getKeyImage(publicKey, privateKey)

	b := make([]byte, 32)

	for i := 0; i < numberOfPKeys; i++ {
		rList[i].FillBytes(b)
		reverseBytes(b)

		qI, err := edwards25519.NewScalar().SetCanonicalBytes(b)
		if err != nil {
			log.Panicln(err)
		}

		rG := edwards25519.NewGeneratorPoint().ScalarMult(qI, basePoint)
		normalize(rG)
		point, err := edwards25519.NewGeneratorPoint().SetBytes(publicKeys[i])
		normalize(point)
		if err != nil {
			log.Panicln(err)
		}
		rH := edwards25519.NewGeneratorPoint().ScalarMult(qI, point)
		normalize(rH)
		if i == s {
			lArray = append(lArray, rG)
			rArray = append(rArray, rH)
			continue
		}

		b = cList[i].FillBytes(b)
		reverseBytes(b)

		wI, err := edwards25519.NewScalar().SetCanonicalBytes(b)
		if err != nil {
			log.Panicln(err)
		}

		cP := edwards25519.NewGeneratorPoint().ScalarMult(wI, point)
		normalize(cP)
		rGcP := edwards25519.NewGeneratorPoint().Add(rG, cP)
		normalize(rGcP)

		cI := edwards25519.NewGeneratorPoint().ScalarMult(wI, keyImage)
		normalize(cI)
		rHcI := edwards25519.NewGeneratorPoint().Add(rH, cI)
		normalize(rHcI)

		lArray = append(lArray, rGcP)
		rArray = append(rArray, rHcI)
	}

	c := big.NewInt(0)
	hash := getHash(message, lArray, rArray)
	c.SetBytes(hash[:])

	sum := big.NewInt(0)
	for i := 0; i < numberOfPKeys; i++ {
		if i != s {
			sum.Add(sum, cList[i])
		}
	}

	pKey := big.NewInt(0)
	pKey.SetBytes(privateKey)

	cList[s] = big.NewInt(0).Mod(big.NewInt(0).Sub(c, sum), order)
	rList[s] = big.NewInt(0).Mod(big.NewInt(0).Sub(rList[s], big.NewInt(0).Mul(cList[s], pKey)), order)

	return &RingSignature{
		KeyImage: keyImage,
		CList:    cList,
		RList:    rList,
	}, nil
}

func getKeyImage(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) *edwards25519.Point {
	pKey := big.NewInt(0)
	pKey.SetBytes(privateKey)

	bp := make([]byte, 64)

	keyImage, _ := edwards25519.NewGeneratorPoint().SetBytes(publicKey)

	pKey.FillBytes(bp)
	reverseBytes(bp)

	ss, err := edwards25519.NewScalar().SetUniformBytes(bp)
	if err != nil {
		log.Panicln(err)
	}

	keyImage.ScalarBaseMult(ss)
	normalize(keyImage)
	return keyImage
}

func (sig *RingSignature) VerifySignature(message string, publicKeys []ed25519.PublicKey) bool {
	numberOfPKeys := len(publicKeys)
	var newLArray []*edwards25519.Point
	var newRArray []*edwards25519.Point

	cExpected := big.NewInt(0)

	b := make([]byte, 32)

	for i := 0; i < numberOfPKeys; i++ {
		sig.RList[i].FillBytes(b)
		reverseBytes(b)

		rI, err := edwards25519.NewScalar().SetCanonicalBytes(b)
		if err != nil {
			log.Panicln(err)
		}
		rG := edwards25519.NewGeneratorPoint().ScalarMult(rI, basePoint)
		normalize(rG)

		point, err := edwards25519.NewGeneratorPoint().SetBytes(publicKeys[i])
		normalize(point)
		if err != nil {
			log.Panicln(err)
		}
		rH := edwards25519.NewGeneratorPoint().ScalarMult(rI, point)
		normalize(rH)

		sig.CList[i].FillBytes(b)
		reverseBytes(b)

		cI, err := edwards25519.NewScalar().SetCanonicalBytes(b)
		if err != nil {
			log.Panicln(err)
		}

		cP := edwards25519.NewGeneratorPoint().ScalarMult(cI, point)
		normalize(cP)
		c_I := edwards25519.NewGeneratorPoint().ScalarMult(cI, sig.KeyImage)
		normalize(c_I)

		currentLValue := edwards25519.NewGeneratorPoint().Add(rG, cP)
		normalize(currentLValue)
		currentRValue := edwards25519.NewGeneratorPoint().Add(rH, c_I)
		normalize(currentRValue)

		newLArray = append(newLArray, currentLValue)
		newRArray = append(newRArray, currentRValue)

		cExpected = big.NewInt(0).Add(cExpected, sig.CList[i]).Mod(cExpected, order)
	}

	cReal := big.NewInt(0)
	hash := getHash(message, newLArray, newRArray)
	cReal.SetBytes(hash[:])
	cReal = big.NewInt(0).Mod(cReal, order)

	return cReal.Cmp(cExpected) == 0
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

func normalize(point *edwards25519.Point) {
	x, y, z, t := point.ExtendedCoordinates()

	z.Invert(z)

	_, _, zOld, _ := point.ExtendedCoordinates()

	multiplyModule(x, z)
	multiplyModule(y, z)
	multiplyModule(z, zOld)

	t.Multiply(x, y)

	_, err := point.SetExtendedCoordinates(x, y, z, t)

	if err != nil {
		log.Panicln(err)
	}

	log.Println(z)
}

func multiplyModule(x *field.Element, y *field.Element) *field.Element {
	x.Multiply(x, y)
	bytes := x.Bytes()
	reverseBytes(bytes)

	bigInt := big.NewInt(0).SetBytes(bytes)
	bigInt.Mod(bigInt, fieldOrder)
	reverseBytes(bytes)
	_, err := x.SetBytes(bytes)

	if err != nil {
		log.Panicln(err)
	}

	return x
}
