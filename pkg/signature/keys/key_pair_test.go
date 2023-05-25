package keys

import (
	curve2 "github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/curve"
	"reflect"
	"testing"
)

func TestBytesToPublic(t *testing.T) {
	montgomeryCurve := curve2.NewCurve25519()
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
		want     curve2.Point
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
			public := keyPair.GetPublicKey()
			if got := reflect.DeepEqual(public.X, tt.want.X) && reflect.DeepEqual(public.Y, tt.want.Y); got != tt.wantBool {
				t.Errorf("BytesToPublic() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicToBytes(t *testing.T) {
	keyPair, _ := Random(curve2.NewCurve25519())

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
			publicBytes := keyPair.PublicToBytes()
			if got := reflect.DeepEqual(publicBytes, tt.want); got != tt.wantBool {
				t.Errorf("PublicToBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newKeyPairFromPrivateKey(t *testing.T) {
	private := PrivateKeyBytes{1}
	public := PublicKeyBytes{3, 50, 184, 109, 215, 145, 12, 67, 215, 234, 153, 100, 93, 235, 162, 178, 10, 68, 251, 21, 43, 52, 151, 126, 226, 45, 190, 80, 119, 13, 3, 98, 8}
	curve := curve2.NewCurve25519()
	keyPair := &KeyPair{curve: curve}
	keyPair.BytesToPrivate(private)
	keyPair.BytesToPublic(public)

	type args struct {
		privateKeyBytes PrivateKeyBytes
		curve           curve2.ICurve
	}
	tests := []struct {
		name     string
		args     args
		want     KeyPair
		wantBool bool
	}{
		{
			name: "Correct key pair generation",
			args: args{
				privateKeyBytes: private,
				curve:           curve,
			},
			want:     *keyPair,
			wantBool: true,
		},
		{
			name: "Incorrect key pair generation",
			args: args{
				privateKeyBytes: PrivateKeyBytes{2},
				curve:           curve,
			},
			want:     *keyPair,
			wantBool: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reflect.DeepEqual(*newKeyPairFromPrivateKey(tt.args.privateKeyBytes, tt.args.curve), tt.want); got != tt.wantBool {
				t.Errorf("newKeyPairFromPrivateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
