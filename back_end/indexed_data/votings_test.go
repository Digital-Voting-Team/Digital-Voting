package indexed_data

import (
	ts "digital-voting/transaction/transaction_specific"
	"reflect"
	"testing"
	"time"
)

func TestVotingProvider_AddNewVoting(t *testing.T) {
	tx1 := ts.NewTxVotingCreation(time.Now(), "Description 1", []string{}, [][33]byte{})
	tx2 := ts.NewTxVotingCreation(time.Now(), "Description 2", []string{}, [][33]byte{})

	vp := NewVotingProvider()

	type args struct {
		tx ts.TxVotingCreation
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Non existing transaction",
			args: args{
				tx: *tx1,
			},
			want: false,
		},
		{
			name: "Existing transaction",
			args: args{
				tx: *tx2,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vp.AddNewVoting(tt.args.tx)
			if _, got := vp.IndexedVotings[tx2.GetHashInBytes()]; got != tt.want {
				t.Errorf("got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVotingProvider_GetTx(t *testing.T) {
	tx1 := ts.NewTxVotingCreation(time.Now(), "Description 1", []string{}, [][33]byte{})
	tx2 := ts.NewTxVotingCreation(time.Now(), "Description 2", []string{}, [][33]byte{})

	vp := NewVotingProvider()
	vp.AddNewVoting(*tx1)

	type args struct {
		hash [32]byte
	}
	tests := []struct {
		name string
		args args
		want ts.TxVotingCreation
	}{
		{
			name: "Existing transaction",
			args: args{
				hash: tx1.GetHashInBytes(),
			},
			want: *tx1,
		},
		{
			name: "Non existing transaction",
			args: args{
				hash: tx2.GetHashInBytes(),
			},
			want: ts.TxVotingCreation{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := vp.GetTx(tt.args.hash); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetTx() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVotingProvider_RemoveVoting(t *testing.T) {
	tx1 := ts.NewTxVotingCreation(time.Now(), "Description 1", []string{}, [][33]byte{})
	tx2 := ts.NewTxVotingCreation(time.Now(), "Description 2", []string{}, [][33]byte{})

	vp := NewVotingProvider()
	vp.AddNewVoting(*tx1)
	vp.AddNewVoting(*tx2)

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
				hash: tx2.GetHashInBytes(),
			},
			want: true,
		},
		{
			name: "Deleted transaction",
			args: args{
				hash: tx1.GetHashInBytes(),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vp.RemoveVoting(tt.args.hash)
			if _, got := vp.IndexedVotings[tx1.GetHashInBytes()]; got != tt.want {
				t.Errorf("got = %v, want %v", got, tt.want)
			}
		})
	}
}
