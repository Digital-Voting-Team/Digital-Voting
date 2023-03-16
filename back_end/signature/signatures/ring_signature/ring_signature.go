package signatures

import (
	"crypto/rand"
	"crypto/sha256"
	curve2 "digital-voting/signature/curve"
	"digital-voting/signature/keys"
	"fmt"
	"log"
	"math/big"
)

type ECDSA_RS struct {
	GenPoint *curve2.Point
	Curve    *curve2.MontgomeryCurve
}

func NewECDSA_RS() *ECDSA_RS {
	curve := curve2.NewCurve25519()
	return &ECDSA_RS{
		GenPoint: curve.G(),
		Curve:    curve,
	}
}

// RingSignature
// https://bytecoin.org/old/whitepaper.pdf
type RingSignature struct {
	KeyImage *curve2.Point `json:"key_image"`
	CList    []*big.Int    `json:"c_list"`
	RList    []*big.Int    `json:"r_list"`
}

func (rs *RingSignature) SignatureToBytes() ([][65]byte, [33]byte) {
	// result[i][0] -> version
	// result[i][1:32] -> CList[i]
	// result[i][32:] -> RList[i]

	result := make([][65]byte, len(rs.CList))

	for i := 0; i < len(result); i++ {
		result[i][0] = '0'
		rs.CList[i].FillBytes(result[i][1:33])
		rs.RList[i].FillBytes(result[i][33:])
	}
	return result, rs.KeyImage.PointToBytes()
}

func BytesToSignature(data [][65]byte, keyImage [33]byte) *RingSignature {
	rs := &RingSignature{
		KeyImage: curve2.BytesToPoint(keyImage, curve2.NewCurve25519()),
		CList:    []*big.Int{},
		RList:    []*big.Int{},
	}

	for i := 0; i < len(data); i++ {
		//version := data[0]
		rs.CList = append(rs.CList, new(big.Int).SetBytes(data[i][1:33]))
		rs.RList = append(rs.RList, new(big.Int).SetBytes(data[i][33:]))
	}

	return rs
}

func (ec *ECDSA_RS) SignBytes(message string, privateKey *big.Int, publicKey [33]byte, publicKeys [][33]byte, s int) (*RingSignature, error) {
	keyPair := new(keys.KeyPair)
	keyPair.PrivateKey = privateKey
	keyPair.BytesToPublic(publicKey)

	pubKeys := make([]*curve2.Point, len(publicKeys))
	for i, pKey := range publicKeys {
		pubKeys[i] = curve2.BytesToPoint(pKey, ec.Curve)
	}

	return ec.Sign(message, keyPair, pubKeys, s)
}

func (ec *ECDSA_RS) Sign(message string, keyPair keys.KP, publicKeys []*curve2.Point, s int) (*RingSignature, error) {
	// Define the size of the ring of public keys that will be used in signing
	numberOfPKeys := len(publicKeys)

	if s < 0 || s >= numberOfPKeys {
		return nil, fmt.Errorf("wrong index of personal key")
	}

	// Pick random c[i] and r[i] from interval [1...N), i from 0 to n-1 inclusive, where n is size of the ring
	// N is the prime order of the base point of the curve
	cList := make([]*big.Int, numberOfPKeys)
	rList := make([]*big.Int, numberOfPKeys)

	var err error
	for i := 0; i < numberOfPKeys; i++ {
		cList[i], err = rand.Int(rand.Reader, ec.Curve.N)
		if err != nil {
			log.Panicln(err)
		}
		rList[i], err = rand.Int(rand.Reader, ec.Curve.N)
		if err != nil {
			log.Panicln(err)
		}
	}

	// This 2 arrays of elliptic curve points will be calculated in cycle and used in hash calculation
	var lArray []*curve2.Point
	var rArray []*curve2.Point

	// Calculating so-called key image which identifies the key pair of signer
	keyImage := keyPair.GetKeyImage()

	// lArray[i] = |r[i]*G, if i==s
	//			   |r[i]*G + c[i]*P[i], else
	// G is base point of the curve,
	// s is signer's public key's ordinal number in the ring,
	// P[i] is i-th public key in the ring.
	//
	// rArray[i] = |r[i]*H_p(P[i]), if i==s
	//			   |r[i]*H_p(P[i]) + c[i]*I, else
	// H_p(P[i]) is deterministic hash-function (Point on curve -> Point on curve) of i-th public key in the ring,
	// I is previously calculated key image.
	for i := 0; i < numberOfPKeys; i++ {
		rI := new(big.Int).Set(rList[i])

		rG, err := ec.Curve.MulPoint(rI, ec.GenPoint)
		if err != nil {
			log.Panicln(err)
		}

		rH, err := ec.Curve.MulPoint(rI, ec.Curve.ComputeDeterministicHash(publicKeys[i].Copy()))
		if err != nil {
			log.Panicln(err)
		}

		// lArray[i] = r[i]*G, if i==s
		// rArray[i] = r[i]*H_p(P[i]), if i==s
		if i == s {
			lArray = append(lArray, rG)
			rArray = append(rArray, rH)
			continue
		}

		cI := new(big.Int).Set(cList[i])

		cP, err := ec.Curve.MulPoint(cI, publicKeys[i].Copy())
		if err != nil {
			log.Panicln(err)
		}

		rGcP, err := ec.Curve.AddPoint(rG, cP)
		if err != nil {
			log.Panicln(err)
		}

		cIPoint, err := ec.Curve.MulPoint(cI, keyImage)
		if err != nil {
			log.Panicln(err)
		}

		rHcI, err := ec.Curve.AddPoint(rH, cIPoint)
		if err != nil {
			log.Panicln(err)
		}

		// lArray[i] = r[i]*G + c[i]*P[i], else
		// rArray[i] = r[i]*H_p(P[i]) + c[i]*I, else
		lArray = append(lArray, rGcP)
		rArray = append(rArray, rHcI)
	}

	// Calculate non-interactive challenge with use of message and 2 previously calculated arrays
	hash := getHash(message, lArray, rArray)
	// Get *Int from this challenge
	c := new(big.Int).SetBytes(hash[:])

	// Calculate sum from 0 to ring size exclusive of c[i]
	sum := new(big.Int)
	for i := 0; i < numberOfPKeys; i++ {
		if i != s {
			sum = new(big.Int).Add(sum, cList[i])
		}
	}
	// Get private key as copy in *Int data type
	pKey := new(big.Int).Set(keyPair.GetPrivateKey())

	// c[s] = (c - sum) mod N
	// c is previously calculated non-interactive challenge,
	// N is the prime order of the base point of the curve.
	//
	// r[s] = r[s] - c[s]*pKey
	// pKey is the signer's private key
	cList[s] = new(big.Int).Mod(new(big.Int).Sub(c, sum), ec.Curve.N)
	rList[s] = new(big.Int).Mod(new(big.Int).Sub(rList[s], new(big.Int).Mul(cList[s], pKey)), ec.Curve.N)

	return &RingSignature{
		KeyImage: keyImage,
		CList:    cList,
		RList:    rList,
	}, nil
}

func (ec *ECDSA_RS) VerifyBytes(message string, publicKeys [][33]byte, signature [][65]byte, keyImage [33]byte) bool {
	pubKeys := make([]*curve2.Point, len(publicKeys))
	for i, pKey := range publicKeys {
		pubKeys[i] = curve2.BytesToPoint(pKey, ec.Curve)
	}

	sig := BytesToSignature(signature, keyImage)

	return ec.Verify(message, pubKeys, sig)
}

func (ec *ECDSA_RS) Verify(message string, publicKeys []*curve2.Point, sig *RingSignature) bool {
	// Define the size of the ring of public keys that will be used in signatures
	numberOfPKeys := len(publicKeys)

	// This 2 arrays of elliptic curve points will be calculated in cycle and used in hash calculation
	var newLArray []*curve2.Point
	var newRArray []*curve2.Point

	// A sum of c[i] in cList store in signatures data structure (will be calculated)
	cExpected := new(big.Int)

	// newLArray[i] = r[i]*G + c[i]*P[i]
	// G is base point of the curve,
	// P[i] is i-th public key in the ring.
	//
	// newRArray[i] = r[i]*H_p(P[i]) + c[i]*I
	// H_p(P[i]) is deterministic hash-function (Point on curve -> Point on curve) of i-th public key in the ring,
	// I is previously calculated key image.
	for i := 0; i < numberOfPKeys; i++ {
		rI := new(big.Int).Set(sig.RList[i])

		rG, err := ec.Curve.MulPoint(rI, ec.GenPoint)
		if err != nil {
			log.Panicln(err)
		}

		rH, err := ec.Curve.MulPoint(rI, ec.Curve.ComputeDeterministicHash(publicKeys[i].Copy()))
		if err != nil {
			log.Panicln(err)
		}

		cI := new(big.Int).Set(sig.CList[i])

		cP, err := ec.Curve.MulPoint(cI, publicKeys[i].Copy())
		if err != nil {
			log.Panicln(err)
		}

		cIPoint, err := ec.Curve.MulPoint(cI, sig.KeyImage)
		if err != nil {
			log.Panicln(err)
		}

		currentLValue, err := ec.Curve.AddPoint(rG, cP)
		if err != nil {
			log.Panicln(err)
		}

		currentRValue, err := ec.Curve.AddPoint(rH, cIPoint)
		if err != nil {
			log.Panicln(err)
		}

		newLArray = append(newLArray, currentLValue)
		newRArray = append(newRArray, currentRValue)

		cExpected = new(big.Int).Mod(new(big.Int).Add(cExpected, sig.CList[i]), ec.Curve.N)
	}

	// Calculate non-interactive challenge with use of message and 2 previously calculated arrays
	hash := getHash(message, newLArray, newRArray)
	// Get *Int from this challenge, mod N
	// N is the prime order of the base point of the curve.
	cReal := new(big.Int).Mod(new(big.Int).SetBytes(hash[:]), ec.Curve.N)

	// Compare the value got as sum of c[i] from signatures data structure
	// and the value calculated as non-interactive challenge.
	// Verification must not pass if values are different.
	return cReal.Cmp(cExpected) == 0
}

func getHash(message string, lArray, rArray []*curve2.Point) [32]byte {
	messageToHash := message

	for i := 0; i < len(lArray); i++ {
		messageToHash += fmt.Sprintf("%v", lArray[i])
	}

	for i := 0; i < len(rArray); i++ {
		messageToHash += fmt.Sprintf("%v", rArray[i])
	}

	return sha256.Sum256([]byte(messageToHash))
}
