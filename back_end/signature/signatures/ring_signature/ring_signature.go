package signatures

import (
	"crypto/rand"
	"crypto/sha256"
	crv "digital-voting/signature/curve"
	"digital-voting/signature/keys"
	"fmt"
	"log"
	"math/big"
)

type ECDSA_RS struct {
	GenPoint *crv.Point
	Curve    *crv.MontgomeryCurve
}

func NewECDSA_RS() *ECDSA_RS {
	curve := crv.NewCurve25519()
	return &ECDSA_RS{
		GenPoint: curve.G(),
		Curve:    curve,
	}
}

// RingSignature
// https://bytecoin.org/old/whitepaper.pdf
type RingSignature struct {
	KeyImage *crv.Point `json:"key_image"`
	CList    []*big.Int `json:"c_list"`
	RList    []*big.Int `json:"r_list"`
}

type RingSignatureBytes [][65]byte
type KeyImageBytes [33]byte

func (rs *RingSignature) SignatureToBytes() (RingSignatureBytes, KeyImageBytes) {
	// result[i][0] -> version
	// result[i][1:32] -> CList[i]
	// result[i][32:] -> RList[i]

	result := make(RingSignatureBytes, len(rs.CList))

	for i := 0; i < len(result); i++ {
		result[i][0] = '0'
		rs.CList[i].FillBytes(result[i][1:33])
		rs.RList[i].FillBytes(result[i][33:])
	}
	return result, KeyImageBytes(rs.KeyImage.PointToBytes())
}

func BytesToSignature(data RingSignatureBytes, keyImage KeyImageBytes) *RingSignature {
	rs := &RingSignature{
		KeyImage: crv.BytesToPoint(crv.PointCompressed(keyImage), crv.NewCurve25519()),
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

func (ec *ECDSA_RS) SignBytes(message string, privateKey keys.PrivateKeyBytes, publicKey keys.PublicKeyBytes, publicKeys []keys.PublicKeyBytes, s int) (*RingSignature, error) {
	keyPair := new(keys.KeyPair)
	keyPair.BytesToPrivate(privateKey)
	keyPair.BytesToPublic(publicKey)

	pubKeys := make([]*crv.Point, len(publicKeys))
	for i, pKey := range publicKeys {
		pubKeys[i] = crv.BytesToPoint(crv.PointCompressed(pKey), ec.Curve)
	}

	return ec.Sign(message, keyPair, pubKeys, s)
}

func (ec *ECDSA_RS) Sign(message string, keyPair keys.KP, publicKeys []*crv.Point, s int) (*RingSignature, error) {
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
	var lArray []*crv.Point
	var rArray []*crv.Point

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

func (ec *ECDSA_RS) VerifyBytes(message string, publicKeys []keys.PublicKeyBytes, signature RingSignatureBytes, keyImage KeyImageBytes) bool {
	pubKeys := make([]*crv.Point, len(publicKeys))
	for i, pKey := range publicKeys {
		pubKeys[i] = crv.BytesToPoint(crv.PointCompressed(pKey), ec.Curve)
	}

	sig := BytesToSignature(signature, keyImage)

	return ec.Verify(message, pubKeys, sig)
}

func (ec *ECDSA_RS) Verify(message string, publicKeys []*crv.Point, sig *RingSignature) bool {
	// Define the size of the ring of public keys that will be used in signatures
	numberOfPKeys := len(publicKeys)

	// This 2 arrays of elliptic curve points will be calculated in cycle and used in hash calculation
	var newLArray []*crv.Point
	var newRArray []*crv.Point

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

func getHash(message string, lArray, rArray []*crv.Point) [32]byte {
	messageToHash := message

	for i := 0; i < len(lArray); i++ {
		messageToHash += fmt.Sprintf("%v", lArray[i])
	}

	for i := 0; i < len(rArray); i++ {
		messageToHash += fmt.Sprintf("%v", rArray[i])
	}

	return sha256.Sum256([]byte(messageToHash))
}
