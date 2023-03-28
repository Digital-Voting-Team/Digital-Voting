package signatures

import (
	"digital-voting/signature/curve"
	"digital-voting/signature/keys"
	"log"
	"math/big"
	"reflect"
	"testing"
)

func TestKeyGeneration(t *testing.T) {
	sign := NewECDSA()
	keyPair1, err := keys.Random(sign.Curve)
	if err != nil {
		log.Panicln(err)
	}

	keyPair2, err := keys.Random(sign.Curve)
	if err != nil {
		log.Panicln(err)
	}
	pk1 := keyPair1.GetPrivateKey()
	pbk1 := keyPair1.GetPublicKey()

	pk2 := keyPair2.GetPrivateKey()
	pbk2 := keyPair2.GetPublicKey()

	if new(big.Int).Sub(pk1, pk2).Sign() == 0 {
		t.Errorf("%v: %v, keys must be different", pk1, pk2)
	}

	if pbk1.Eq(pbk2) {
		t.Errorf("%v: %v, keys must be different", pbk1, pbk2)
	}
}

func TestVerify(t *testing.T) {
	sign := NewECDSA()
	keyPair1, err := keys.Random(sign.Curve)
	if err != nil {
		log.Panicln(err)
	}

	keyPair2, err := keys.Random(sign.Curve)
	if err != nil {
		log.Panicln(err)
	}
	pk1 := keyPair1.GetPrivateKey()
	pbk1 := keyPair1.GetPublicKey()

	pk2 := keyPair2.GetPrivateKey()
	pbk2 := keyPair2.GetPublicKey()

	msg := "String ...."
	msg2 := "String2 ...."
	signature := sign.Sign(msg, pk1)
	signature1 := sign.Sign(msg, pk2)
	type fields struct {
		GenPoint *curve.Point
		Curve    *curve.MontgomeryCurve
	}
	type args struct {
		publicKey *curve.Point
		message   string
		signature *SingleSignature
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "Should verify (pk1, pbk1, correct message)",
			args: args{
				publicKey: pbk1,
				message:   msg,
				signature: signature,
			},
			want: true,
		},
		{
			name: "Should not verify (pk1, pbk1, incorrect message)",
			args: args{
				publicKey: pbk1,
				message:   msg2,
				signature: signature,
			},
			want: false,
		},
		{
			name: "Should not verify (pk1, pbk2, correct message)",
			args: args{
				publicKey: pbk2,
				message:   msg,
				signature: signature,
			},
			want: false,
		},
		{
			name: "Should verify (pk2, pbk2, correct message)",
			args: args{
				publicKey: pbk2,
				message:   msg,
				signature: signature1,
			},
			want: true,
		},
		{
			name: "Should not verify (pk2, pbk2, incorrect message)",
			args: args{
				publicKey: pbk2,
				message:   msg2,
				signature: signature1,
			},
			want: false,
		},
		{
			name: "Should not verify (pk2, pbk1, correct message)",
			args: args{
				publicKey: pbk1,
				message:   msg,
				signature: signature1,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sign.Verify(tt.args.message, tt.args.publicKey, tt.args.signature); got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBytesToSignature(t *testing.T) {
	sign := NewECDSA()
	keyPair, _ := keys.Random(sign.Curve)
	message := "1"

	signature := sign.Sign(message, keyPair.GetPrivateKey())
	sigBytes := signature.SignatureToBytes()

	signature1 := sign.Sign(message+"1", keyPair.GetPrivateKey())

	type args struct {
		data SingleSignatureBytes
	}
	tests := []struct {
		name     string
		args     args
		want     SingleSignature
		wantBool bool
	}{
		{
			name: "Correct conversion from bytes",
			args: args{
				sigBytes,
			},
			want:     *signature,
			wantBool: true,
		},
		{
			name: "Incorrect conversion from bytes",
			args: args{
				sigBytes,
			},
			want:     *signature1,
			wantBool: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reflect.DeepEqual(*BytesToSignature(tt.args.data), tt.want); got != tt.wantBool {
				t.Errorf("BytesToSignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignatureToBytes(t *testing.T) {
	sign := NewECDSA()
	keyPair, _ := keys.Random(sign.Curve)
	message := "1"

	signature := sign.Sign(message, keyPair.GetPrivateKey())
	sigBytes := signature.SignatureToBytes()

	tests := []struct {
		name     string
		want     SingleSignatureBytes
		wantBool bool
	}{
		{
			name:     "Correct conversion to bytes",
			want:     sigBytes,
			wantBool: true,
		},
		{
			name:     "Incorrect conversion to bytes",
			want:     SingleSignatureBytes{12, 10, 11},
			wantBool: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reflect.DeepEqual(signature.SignatureToBytes(), tt.want); got != tt.wantBool {
				t.Errorf("SignatureToBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}
