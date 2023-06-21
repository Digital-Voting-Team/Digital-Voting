package indexed_votings

import (
	"reflect"
	"testing"
)

func TestVotingProvider_AddNewVoting(t *testing.T) {
	tx1 := VotingDTO{Hash: [32]byte{1}, VotingDescription: [1024]byte{1}}
	tx2 := VotingDTO{Hash: [32]byte{2}, VotingDescription: [1024]byte{2}}

	vp := NewVotingManager()

	type args struct {
		tx VotingDTO
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Non existing transaction",
			args: args{
				tx: tx1,
			},
			want: false,
		},
		{
			name: "Existing transaction",
			args: args{
				tx: tx2,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vp.AddNewVoting(tt.args.tx)
			if _, got := vp.IndexedVotings[tx2.Hash]; got != tt.want {
				t.Errorf("got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVotingProvider_GetTx(t *testing.T) {
	tx1 := VotingDTO{Hash: [32]byte{1}, VotingDescription: [1024]byte{1}}
	tx2 := VotingDTO{Hash: [32]byte{2}, VotingDescription: [1024]byte{2}}

	vp := NewVotingManager()
	vp.AddNewVoting(tx1)

	type args struct {
		hash [32]byte
	}
	tests := []struct {
		name string
		args args
		want VotingDTO
	}{
		{
			name: "Existing transaction",
			args: args{
				hash: tx1.Hash,
			},
			want: tx1,
		},
		{
			name: "Non existing transaction",
			args: args{
				hash: tx2.Hash,
			},
			want: VotingDTO{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := vp.GetVoting(tt.args.hash); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetVoting() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVotingProvider_RemoveVoting(t *testing.T) {
	tx1 := VotingDTO{Hash: [32]byte{1}, VotingDescription: [1024]byte{1}}
	tx2 := VotingDTO{Hash: [32]byte{2}, VotingDescription: [1024]byte{2}}

	vp := NewVotingManager()
	vp.AddNewVoting(tx1)
	vp.AddNewVoting(tx2)

	type args struct {
		hash [32]byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Not deleted transaction",
			args: args{
				hash: tx2.Hash,
			},
			want: true,
		},
		{
			name: "Deleted transaction",
			args: args{
				hash: tx1.Hash,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vp.RemoveVoting(tt.args.hash)
			if _, got := vp.IndexedVotings[tx1.Hash]; got != tt.want {
				t.Errorf("got = %v, want %v", got, tt.want)
			}
		})
	}
}
