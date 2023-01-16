package ring_signature

import (
	curve2 "digital-voting/curve"
	"digital-voting/keys"
	"log"
	"math/big"
	"reflect"
	"testing"
	"time"
)

func TestVerifySignature(t *testing.T) {
	keyPair, err := keys.ParseKeyPair(time.Now().String(), curve)
	if err != nil {
		log.Panicln(err)
	}
	publicKey := keyPair.GetPublicKey()

	var publicKeys []*curve2.Point
	publicKeys = append(publicKeys, publicKey)

	for i := 0; i < 5; i++ {
		tempKeyPair, err := keys.ParseKeyPair(time.Now().String(), curve)
		if err != nil {
			log.Panicln(err)
		}
		publicKeys = append(publicKeys, tempKeyPair.GetPublicKey())
	}

	message := "asd21312313"
	s := 0

	ringSignature, err := Sign(message, keyPair, publicKeys, s)
	if err != nil {
		log.Panicln(err)
	}

	keyPair1, _ := keys.ParseKeyPair(time.Now().String(), curve)
	ringSignature1, err := Sign(message, keyPair1, publicKeys, s)
	if err != nil {
		log.Panicln(err)
	}

	var publicKeys1 []*curve2.Point

	for i := 0; i < 5; i++ {
		tempKeyPair, err := keys.ParseKeyPair(time.Now().String(), curve)
		if err != nil {
			log.Panicln(err)
		}
		publicKeys1 = append(publicKeys1, tempKeyPair.GetPublicKey())
	}

	type fields struct {
		KeyImage *curve2.Point
		CList    []*big.Int
		RList    []*big.Int
	}
	type args struct {
		message    string
		publicKeys []*curve2.Point
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
			if got := sig.Verify(tt.args.message, tt.args.publicKeys); got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getHash(t *testing.T) {
	var lArray []*curve2.Point
	var rArray []*curve2.Point

	lArray = append(lArray, curve.G())
	rArray = append(rArray, curve.G())

	type args struct {
		message string
		lArray  []*curve2.Point
		rArray  []*curve2.Point
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
