package indexed_data

import (
	"digital-voting/signature/keys"
	ts "digital-voting/transaction/transaction_specific"
	"reflect"
	"testing"
)

func TestGroupProvider_AddNewGroup(t *testing.T) {
	tx1 := ts.NewTxGroupCreation("1", []keys.PublicKeyBytes{{1}, {2}}...)
	tx2 := ts.NewTxGroupCreation("2", []keys.PublicKeyBytes{{3}, {4}}...)

	gp := NewGroupProvider()

	type args struct {
		tx ts.TxGroupCreation
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
			gp.AddNewGroup(tt.args.tx)
			if _, got := gp.IndexedGroups[tx2.GroupIdentifier]; got != tt.want {
				t.Errorf("got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGroupProvider_GetTx(t *testing.T) {
	tx1 := ts.NewTxGroupCreation("1", []keys.PublicKeyBytes{{1}, {2}}...)
	tx2 := ts.NewTxGroupCreation("2", []keys.PublicKeyBytes{{3}, {4}}...)

	gp := NewGroupProvider()
	gp.AddNewGroup(*tx1)

	type args struct {
		identifier [33]byte
	}
	tests := []struct {
		name string
		args args
		want ts.TxGroupCreation
	}{
		{
			name: "Existing transaction",
			args: args{
				identifier: tx1.GroupIdentifier,
			},
			want: *tx1,
		},
		{
			name: "Non existing transaction",
			args: args{
				identifier: tx2.GroupIdentifier,
			},
			want: ts.TxGroupCreation{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gp.GetTx(tt.args.identifier); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetTx() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGroupProvider_IsGroupMember(t *testing.T) {
	tx1 := ts.NewTxGroupCreation("1", []keys.PublicKeyBytes{{1}, {2}}...)
	tx2 := ts.NewTxGroupCreation("2", []keys.PublicKeyBytes{{3}, {4}}...)
	gp := NewGroupProvider()
	gp.AddNewGroup(*tx1)

	type args struct {
		groupIdentifier [33]byte
		publicKey       keys.PublicKeyBytes
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "A group member",
			args: args{
				groupIdentifier: tx1.GroupIdentifier,
				publicKey:       keys.PublicKeyBytes{1},
			},
			want: true,
		},
		{
			name: "Not a group member",
			args: args{
				groupIdentifier: tx1.GroupIdentifier,
				publicKey:       keys.PublicKeyBytes{3},
			},
			want: false,
		},
		{
			name: "Non existing group",
			args: args{
				groupIdentifier: tx2.GroupIdentifier,
				publicKey:       keys.PublicKeyBytes{1},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gp.IsGroupMember(tt.args.groupIdentifier, tt.args.publicKey); got != tt.want {
				t.Errorf("IsGroupMember() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGroupProvider_RemoveGroup(t *testing.T) {
	tx1 := ts.NewTxGroupCreation("1", []keys.PublicKeyBytes{{1}, {2}}...)
	tx2 := ts.NewTxGroupCreation("2", []keys.PublicKeyBytes{{3}, {4}}...)

	gp := NewGroupProvider()
	gp.AddNewGroup(*tx1)

	type args struct {
		identifier [33]byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Not deleted transaction",
			args: args{
				identifier: tx2.GroupIdentifier,
			},
			want: true,
		},
		{
			name: "Deleted transaction",
			args: args{
				identifier: tx1.GroupIdentifier,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gp.RemoveGroup(tt.args.identifier)
			if _, got := gp.IndexedGroups[tx1.GroupIdentifier]; got != tt.want {
				t.Errorf("got = %v, want %v", got, tt.want)
			}
		})
	}
}
