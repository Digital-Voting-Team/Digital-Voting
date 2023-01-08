package main

import (
	"digital-voting/signature/ring_signature/ecc"

	"log"
)

func main() {
	curve := ecc.NewCurve25519()
	privateKey, publicKey := ecc.GetKeyPair(curve)

	var publicKeys []*ecc.Point
	publicKeys = append(publicKeys, publicKey)

	for i := 0; i < 5; i++ {
		_, publicKey := ecc.GetKeyPair(curve)
		publicKeys = append(publicKeys, publicKey)
	}

	message := "asd21312313"

	signature, err := SignMessage(message, privateKey, publicKey, publicKeys, 0)
	if err != nil {
		log.Panicln(err)
	}

	isVerified := signature.VerifySignature(message, publicKeys)
	log.Println(isVerified)
}
