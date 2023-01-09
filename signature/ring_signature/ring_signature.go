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

// RingSignature
// https://bytecoin.org/old/whitepaper.pdf
type RingSignature struct {
	KeyImage *signature.Point
	CList    []*big.Int
	RList    []*big.Int
}

func SignMessage(message string, privateKey *big.Int, publicKey *signature.Point, publicKeys []*signature.Point, s int) (*RingSignature, error) {
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
		cList[i], err = rand.Int(rand.Reader, curve.N)
		if err != nil {
			log.Panicln(err)
		}
		rList[i], err = rand.Int(rand.Reader, curve.N)
		if err != nil {
			log.Panicln(err)
		}
	}

	// This 2 arrays of elliptic curve points will be calculated in cycle and used in hash calculation
	var lArray []*signature.Point
	var rArray []*signature.Point

	// Calculating so-called key image which identifies the key pair of signer
	keyImage := signature.GetKeyImage(curve, publicKey, privateKey)

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

		rG, err := curve.MulPoint(rI, curve.G())
		if err != nil {
			log.Panicln(err)
		}

		rH, err := curve.MulPoint(rI, curve.ComputeDeterministicHash(publicKeys[i].Copy()))
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

		cP, err := curve.MulPoint(cI, publicKeys[i].Copy())
		if err != nil {
			log.Panicln(err)
		}

		rGcP, err := curve.AddPoint(rG, cP)
		if err != nil {
			log.Panicln(err)
		}

		cIPoint, err := curve.MulPoint(cI, keyImage)
		if err != nil {
			log.Panicln(err)
		}

		rHcI, err := curve.AddPoint(rH, cIPoint)
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
	pKey := new(big.Int).Set(privateKey)

	// c[s] = (c - sum) mod N
	// c is previously calculated non-interactive challenge,
	// N is the prime order of the base point of the curve.
	//
	// r[s] = r[s] - c[s]*pKey
	// pKey is the signer's private key
	cList[s] = new(big.Int).Mod(new(big.Int).Sub(c, sum), curve.N)
	rList[s] = new(big.Int).Mod(new(big.Int).Sub(rList[s], new(big.Int).Mul(cList[s], pKey)), curve.N)

	return &RingSignature{
		KeyImage: keyImage,
		CList:    cList,
		RList:    rList,
	}, nil
}

func (sig *RingSignature) VerifySignature(message string, publicKeys []*signature.Point) bool {
	// Define the size of the ring of public keys that will be used in signature
	numberOfPKeys := len(publicKeys)

	// This 2 arrays of elliptic curve points will be calculated in cycle and used in hash calculation
	var newLArray []*signature.Point
	var newRArray []*signature.Point

	// A sum of c[i] in cList store in signature data structure (will be calculated)
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

	// Calculate non-interactive challenge with use of message and 2 previously calculated arrays
	hash := getHash(message, newLArray, newRArray)
	// Get *Int from this challenge, mod N
	// N is the prime order of the base point of the curve.
	cReal := new(big.Int).Mod(new(big.Int).SetBytes(hash[:]), curve.N)

	// Compare the value got as sum of c[i] from signature data structure
	// and the value calculated as non-interactive challenge.
	// Verification must not pass if values are different.
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
