package keys

import (
	"digital-voting/signature/curve"
	"reflect"
	"testing"
)

func TestBytesToPublic(t *testing.T) {
	montgomeryCurve := curve.NewCurve25519()
	keyPair, _ := Random(montgomeryCurve)
	keyPair1, _ := Random(montgomeryCurve)

	publicKey := keyPair.GetPublicKey()
	publicKeyBytes := keyPair.PublicToBytes()

	type args struct {
		data PublicKeyBytes
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
	keyPair, _ := Random(curve.NewCurve25519())

	publicKeyBytes := keyPair.PublicToBytes()

	tests := []struct {
		name     string
		want     PublicKeyBytes
		wantBool bool
	}{
		{
			name:     "Correct conversion to bytes",
			want:     publicKeyBytes,
			wantBool: true,
		},
		{
			name:     "Incorrect conversion to bytes",
			want:     PublicKeyBytes{12, 10, 11},
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
