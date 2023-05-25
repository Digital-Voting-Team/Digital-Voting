package signatures

import (
	crv "github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/curve"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
	"log"
	"math/big"
	"reflect"
	"testing"
)

func TestVerifySignature(t *testing.T) {
	sign := NewECDSA_RS()
	keyPair, err := keys.Random(sign.Curve)
	if err != nil {
		log.Panicln(err)
	}
	publicKey := keyPair.GetPublicKey()

	var publicKeys []*crv.Point
	publicKeys = append(publicKeys, publicKey)

	for i := 0; i < 5; i++ {
		tempKeyPair, err := keys.Random(sign.Curve)
		if err != nil {
			log.Panicln(err)
		}
		publicKeys = append(publicKeys, tempKeyPair.GetPublicKey())
	}

	message := "asd21312313"
	s := 0

	ringSignature, err := sign.Sign(message, keyPair, publicKeys, s)
	if err != nil {
		log.Panicln(err)
	}

	keyPair1, _ := keys.Random(sign.Curve)
	ringSignature1, err := sign.Sign(message, keyPair1, publicKeys, s)
	if err != nil {
		log.Panicln(err)
	}

	var publicKeys1 []*crv.Point

	for i := 0; i < 5; i++ {
		tempKeyPair, err := keys.Random(sign.Curve)
		if err != nil {
			log.Panicln(err)
		}
		publicKeys1 = append(publicKeys1, tempKeyPair.GetPublicKey())
	}

	type fields struct {
		KeyImage *crv.Point
		CList    []*big.Int
		RList    []*big.Int
	}
	type args struct {
		message    string
		publicKeys []*crv.Point
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "Correct ring signatures",
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
			if got := sign.Verify(tt.args.message, tt.args.publicKeys, sig); got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getHash(t *testing.T) {
	sign := NewECDSA_RS()
	var lArray []*crv.Point
	var rArray []*crv.Point

	lArray = append(lArray, sign.GenPoint)
	rArray = append(rArray, sign.GenPoint)

	type args struct {
		message string
		lArray  []*crv.Point
		rArray  []*crv.Point
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
			if got := reflect.DeepEqual(getHash(tt.args.message, tt.args.lArray, tt.args.rArray), tt.want); got != tt.wantBool {
				t.Errorf("getHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBytesToSignature(t *testing.T) {
	sign := NewECDSA_RS()

	keyPair, err := keys.Random(sign.Curve)
	if err != nil {
		log.Panicln(err)
	}
	publicKey := keyPair.GetPublicKey()

	var publicKeys []*crv.Point
	publicKeys = append(publicKeys, publicKey)

	for i := 0; i < 5; i++ {
		tempKeyPair, err := keys.Random(sign.Curve)
		if err != nil {
			log.Panicln(err)
		}
		publicKeys = append(publicKeys, tempKeyPair.GetPublicKey())
	}
	message := "1"

	signature, _ := sign.Sign(message, keyPair, publicKeys, 0)
	sigBytes, image := signature.SignatureToBytes()

	signature1, _ := sign.Sign(message+"1", keyPair, publicKeys, 0)
	sigBytes1, image1 := signature1.SignatureToBytes()

	type args struct {
		data     RingSignatureBytes
		keyImage KeyImageBytes
	}
	tests := []struct {
		name     string
		args     args
		want     RingSignature
		wantBool bool
	}{
		{
			name: "Correct conversion from bytes",
			args: args{
				data:     sigBytes,
				keyImage: image,
			},
			want:     *signature,
			wantBool: true,
		},
		{
			name: "Incorrect conversion from bytes",
			args: args{
				data:     sigBytes1,
				keyImage: image1,
			},
			want:     *signature,
			wantBool: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reflect.DeepEqual(*BytesToSignature(tt.args.data, tt.args.keyImage), tt.want); got != tt.wantBool {
				t.Errorf("BytesToSignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignatureToBytes(t *testing.T) {
	sign := NewECDSA_RS()

	keyPair, err := keys.Random(sign.Curve)
	if err != nil {
		log.Panicln(err)
	}
	publicKey := keyPair.GetPublicKey()

	var publicKeys []*crv.Point
	publicKeys = append(publicKeys, publicKey)

	for i := 0; i < 5; i++ {
		tempKeyPair, err := keys.Random(sign.Curve)
		if err != nil {
			log.Panicln(err)
		}
		publicKeys = append(publicKeys, tempKeyPair.GetPublicKey())
	}
	message := "1"

	signature, _ := sign.Sign(message, keyPair, publicKeys, 0)
	sigBytes, image := signature.SignatureToBytes()

	signature1, _ := sign.Sign(message+"1", keyPair, publicKeys, 0)
	sigBytes1, image1 := signature1.SignatureToBytes()

	tests := []struct {
		name     string
		want     RingSignatureBytes
		want1    KeyImageBytes
		wantBool bool
	}{
		{
			name:     "Correct conversion to bytes",
			want:     sigBytes,
			want1:    image,
			wantBool: true,
		},
		{
			name:     "Incorrect conversion to bytes",
			want:     sigBytes1,
			want1:    image1,
			wantBool: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := signature.SignatureToBytes()
			gotBool := reflect.DeepEqual(got, tt.want) && reflect.DeepEqual(got1, tt.want1)
			if gotBool != tt.wantBool {
				t.Errorf("SignatureToBytes() got = %v, %v, want %v, %v", got, got1, tt.want, tt.want1)
			}
		})
	}
}
