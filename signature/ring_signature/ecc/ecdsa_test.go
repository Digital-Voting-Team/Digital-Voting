package ecc

import (
	"math/big"
	"testing"
)

func TestECDSA(t *testing.T) {
	sign := NewECDSA()
	pk1, pbk1 := GetKeyPair(NewCurve25519())
	pk2, pbk2 := GetKeyPair(NewCurve25519())

	msg := "String ...."
	msg2 := "String2 ...."
	r, s := sign.Sign(pk1, msg)

	if !sign.Verify(*pbk1, msg, r, s) {
		t.Errorf("Should verify (pk1, pbk1, correct message)")
	}

	if sign.Verify(*pbk1, msg2, r, s) {
		t.Errorf("Should not verify (pk1, pbk1, incorrect message)")
	}

	if sign.Verify(*pbk2, msg, r, s) {
		t.Errorf("Should not verify (pk1, pbk2, correct message)")
	}

	r, s = sign.Sign(pk2, msg)

	if !sign.Verify(*pbk2, msg, r, s) {
		t.Errorf("Should verify (pk2, pbk2, correct message)")
	}

	if sign.Verify(*pbk2, msg2, r, s) {
		t.Errorf("Should not verify (pk2, pbk2, incorrect message)")
	}

	if sign.Verify(*pbk1, msg, r, s) {
		t.Errorf("Should not verify (pk2, pbk1, correct message)")
	}
}

func TestKeyGeneration(t *testing.T) {
	pk1, pbk1 := GetKeyPair(NewCurve25519())
	pk2, pbk2 := GetKeyPair(NewCurve25519())

	if new(big.Int).Sub(pk1, pk2).Sign() == 0 {
		t.Errorf("%v: %v, keys must be different", pk1, pk2)
	}

	if pbk1.Eq(pbk2) {
		t.Errorf("%v: %v, keys must be different", pbk1, pbk2)
	}
}
