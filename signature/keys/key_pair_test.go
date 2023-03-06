package keys

import (
	"crypto/sha256"
	"digital-voting/signature/curve"
	sig "digital-voting/signature/signatures/single_signature"
	"reflect"
	"testing"
	"time"
)

func TestBytesToPublic(t *testing.T) {
	sign := sig.NewECDSA()
	keyPair, _ := FromRawSeed(sha256.Sum256([]byte(time.Now().String())), sign.Curve)
	keyPair1, _ := FromRawSeed(sha256.Sum256([]byte(time.Now().String())), sign.Curve)

	publicKey := keyPair.GetPublicKey()
	publicKeyBytes := publicKey.PointToBytes()

	type args struct {
		data [33]byte
	}
	tests := []struct {
		name     string
		args     args
		want     curve.Point
		wantBool bool
	}{
		{
			name: "Correct conversion from bytes",
			args: args{
				data: publicKeyBytes,
			},
			want:     *publicKey,
			wantBool: true,
		},
		{
			name: "Incorrect conversion from bytes",
			args: args{
				data: publicKeyBytes,
			},
			want:     *keyPair1.GetPublicKey(),
			wantBool: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair.BytesToPublic(tt.args.data)
			if got := keyPair.GetPublicKey(); tt.wantBool && (!reflect.DeepEqual(got.X, tt.want.X) || !reflect.DeepEqual(got.Y, tt.want.Y)) {
				t.Errorf("BytesToPublic() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicToBytes(t *testing.T) {
	sign := sig.NewECDSA()
	keyPair, _ := FromRawSeed(sha256.Sum256([]byte(time.Now().String())), sign.Curve)

	publicKey := keyPair.GetPublicKey()
	publicKeyBytes := publicKey.PointToBytes()

	tests := []struct {
		name     string
		want     [33]byte
		wantBool bool
	}{
		{
			name:     "Correct conversion to bytes",
			want:     publicKeyBytes,
			wantBool: true,
		},
		{
			name:     "Incorrect conversion to bytes",
			want:     [33]byte{12, 10, 11},
			wantBool: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := keyPair.PublicToBytes(); tt.wantBool && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PublicToBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}
