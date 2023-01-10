package ring_signature

import (
	"digital-voting/signature"
	"log"
	"math/big"
	"reflect"
	"testing"
)

func TestVerifySignature(t *testing.T) {
	privateKey, publicKey := signature.GetKeyPair(curve)

	var publicKeys []*signature.Point
	publicKeys = append(publicKeys, publicKey)

	for i := 0; i < 5; i++ {
		_, publicKey := signature.GetKeyPair(curve)
		publicKeys = append(publicKeys, publicKey)
	}

	message := "asd21312313"
	s := 0

	ringSignature, err := SignMessage(message, privateKey, publicKey, publicKeys, s)
	if err != nil {
		log.Panicln(err)
	}

	privateKey1, publicKey1 := signature.GetKeyPair(curve)
	ringSignature1, err := SignMessage(message, privateKey1, publicKey1, publicKeys, s)
	if err != nil {
		log.Panicln(err)
	}

	var publicKeys1 []*signature.Point

	for i := 0; i < 5; i++ {
		_, publicKey := signature.GetKeyPair(curve)
		publicKeys1 = append(publicKeys1, publicKey)
	}

	type fields struct {
		KeyImage *signature.Point
		CList    []*big.Int
		RList    []*big.Int
	}
	type args struct {
		message    string
		publicKeys []*signature.Point
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "Correct ring signature",
			fields: fields{
				KeyImage: ringSignature.KeyImage,
				CList:    ringSignature.CList,
				RList:    ringSignature.RList,
			},
			args: args{
				message:    message,
				publicKeys: publicKeys,
			},
			want: true,
		},
		{
			name: "Wrong message",
			fields: fields{
				KeyImage: ringSignature.KeyImage,
				CList:    ringSignature.CList,
				RList:    ringSignature.RList,
			},
			args: args{
				message:    "message",
				publicKeys: publicKeys,
			},
			want: false,
		},
		{
			name: "Wrong ring of public keys",
			fields: fields{
				KeyImage: ringSignature.KeyImage,
				CList:    ringSignature.CList,
				RList:    ringSignature.RList,
			},
			args: args{
				message:    message,
				publicKeys: publicKeys1,
			},
			want: false,
		},
		{
			name: "Wrong key pair",
			fields: fields{
				KeyImage: ringSignature1.KeyImage,
				CList:    ringSignature1.CList,
				RList:    ringSignature1.RList,
			},
			args: args{
				message:    message,
				publicKeys: publicKeys,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := &RingSignature{
				KeyImage: tt.fields.KeyImage,
				CList:    tt.fields.CList,
				RList:    tt.fields.RList,
			}
			if got := sig.VerifySignature(tt.args.message, tt.args.publicKeys); got != tt.want {
				t.Errorf("VerifySignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getHash(t *testing.T) {
	var lArray []*signature.Point
	var rArray []*signature.Point

	lArray = append(lArray, curve.G())
	rArray = append(rArray, curve.G())

	type args struct {
		message string
		lArray  []*signature.Point
		rArray  []*signature.Point
	}
	tests := []struct {
		name     string
		args     args
		want     [32]byte
		wantBool bool
	}{
		{
			name: "Correct hash",
			args: args{
				message: "asd",
				lArray:  lArray,
				rArray:  rArray,
			},
			want:     [32]byte{198, 10, 124, 8, 22, 188, 210, 198, 249, 30, 122, 167, 195, 31, 101, 231, 167, 117, 147, 70, 242, 245, 40, 33, 94, 203, 243, 187, 252, 204, 87, 225},
			wantBool: true,
		},
		{
			name: "Incorrect hash",
			args: args{
				message: "asd",
				lArray:  lArray,
				rArray:  rArray,
			},
			want:     [32]byte{},
			wantBool: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getHash(tt.args.message, tt.args.lArray, tt.args.rArray); !reflect.DeepEqual(got, tt.want) && tt.wantBool {
				t.Errorf("getHash() = %v, want %v", got, tt.want)
			}
		})
	}
}
