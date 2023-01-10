package single_signature

import (
	"digital-voting/signature"
	"math/big"
	"testing"
)

func TestKeyGeneration(t *testing.T) {
	pk1, pbk1 := signature.GetKeyPair(signature.NewCurve25519())
	pk2, pbk2 := signature.GetKeyPair(signature.NewCurve25519())

	if new(big.Int).Sub(pk1, pk2).Sign() == 0 {
		t.Errorf("%v: %v, keys must be different", pk1, pk2)
	}

	if pbk1.Eq(pbk2) {
		t.Errorf("%v: %v, keys must be different", pbk1, pbk2)
	}
}

func TestVerify(t *testing.T) {
	sign := NewECDSA()
	pk1, pbk1 := signature.GetKeyPair(signature.NewCurve25519())
	pk2, pbk2 := signature.GetKeyPair(signature.NewCurve25519())

	msg := "String ...."
	msg2 := "String2 ...."
	r, s := sign.Sign(pk1, msg)
	r1, s1 := sign.Sign(pk2, msg)
	type fields struct {
		GenPoint *signature.Point
		Curve    *signature.MontgomeryCurve
	}
	type args struct {
		publicKey *signature.Point
		message   string
		r         *big.Int
		s         *big.Int
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
				r:         r,
				s:         s,
			},
			want: true,
		},
		{
			name: "Should not verify (pk1, pbk1, incorrect message)",
			args: args{
				publicKey: pbk1,
				message:   msg2,
				r:         r,
				s:         s,
			},
			want: false,
		},
		{
			name: "Should not verify (pk1, pbk2, correct message)",
			args: args{
				publicKey: pbk2,
				message:   msg,
				r:         r,
				s:         s,
			},
			want: false,
		},
		{
			name: "Should verify (pk2, pbk2, correct message)",
			args: args{
				publicKey: pbk2,
				message:   msg,
				r:         r1,
				s:         s1,
			},
			want: true,
		},
		{
			name: "Should not verify (pk2, pbk2, incorrect message)",
			args: args{
				publicKey: pbk2,
				message:   msg2,
				r:         r1,
				s:         s1,
			},
			want: false,
		},
		{
			name: "Should not verify (pk2, pbk1, correct message)",
			args: args{
				publicKey: pbk1,
				message:   msg,
				r:         r1,
				s:         s1,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sign.Verify(tt.args.publicKey, tt.args.message, tt.args.r, tt.args.s); got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}
