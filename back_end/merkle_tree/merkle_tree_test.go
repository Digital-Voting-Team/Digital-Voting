package merkle_tree

import (
	"crypto/sha256"
	"log"
	"reflect"
	"testing"
)

type StringContent struct {
	x string
}

// CalculateHash hashes the values of a TestContent
func (t StringContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// Equals tests for equality of two Contents
func (t StringContent) Equals(other Content) (bool, error) {
	return t.x == other.(StringContent).x, nil
}

func TestMerkleTree_MerkleRoot(t *testing.T) {
	list := []Content{StringContent{x: "Hello"}, StringContent{x: "Hi"}, StringContent{x: "Hey"}, StringContent{x: "Hola"}}
	tree, err := NewTree(list)
	if err != nil {
		log.Fatal(err)
	}

	tests := []struct {
		name string
		want []byte
	}{
		{
			name: "Check on string",
			want: []byte{95, 48, 204, 128, 19, 59, 147, 148, 21, 110, 36, 178, 51, 240, 196, 190, 50, 178, 78, 68, 187, 51, 129, 240, 44, 123, 165, 38, 25, 208, 254, 188},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tree.MerkleRoot(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MerkleRoot() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMerkleTree_VerifyContent(t *testing.T) {
	list := []Content{StringContent{x: "Hello"}, StringContent{x: "Hi"}, StringContent{x: "Hey"}, StringContent{x: "Hola"}}
	tree, err := NewTree(list)
	if err != nil {
		log.Fatal(err)
	}

	type args struct {
		content Content
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name:    "Check on string",
			args:    args{StringContent{x: "Hey"}},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tree.VerifyContent(tt.args.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyContent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("VerifyContent() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMerkleTree_VerifyTree(t *testing.T) {
	list := []Content{StringContent{x: "Hello"}, StringContent{x: "Hi"}, StringContent{x: "Hey"}, StringContent{x: "Hola"}}
	tree, err := NewTree(list)
	if err != nil {
		log.Fatal(err)
	}

	tests := []struct {
		name    string
		want    bool
		wantErr bool
	}{
		{
			name:    "Check_on_string",
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tree.VerifyTree()
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyTree() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("VerifyTree() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewTree(t *testing.T) {
	list := []Content{StringContent{x: "Hello"}, StringContent{x: "Hi"}, StringContent{x: "Hey"}, StringContent{x: "Hola"}}
	tree, err := NewTree(list)
	if err != nil {
		log.Fatal(err)
	}

	type args struct {
		cs []Content
	}
	tests := []struct {
		name    string
		args    args
		want    *MerkleTree
		wantErr bool
	}{
		{
			name:    "Check on string",
			args:    args{[]Content{StringContent{x: "Hello"}, StringContent{x: "Hi"}, StringContent{x: "Hey"}, StringContent{x: "Hola"}}},
			want:    tree,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewTree(tt.args.cs)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTree() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.Root.Hash, tt.want.Root.Hash) {
				t.Errorf("NewTree() got = %v, want %v", got.Root.Hash, tt.want.Root.Hash)
			}
		})
	}
}
