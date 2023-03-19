package validation

import (
	"digital-voting/transaction"
	"digital-voting/transaction/transaction_specific"
	"testing"
	"time"
)

func TestIsInMemPool(t *testing.T) {
	v := &Validator{}

	groupName := "EPS-41"
	membersPublicKeys := [][33]byte{}
	membersPublicKeys = append(membersPublicKeys, [33]byte{1, 2, 3})
	grpCreationBody := transaction_specific.NewTxGroupCreation(groupName, membersPublicKeys...)
	txGroupCreation := transaction.NewTransaction(1, grpCreationBody)
	v.MemPool = append(v.MemPool, txGroupCreation)

	expirationDate := time.Now()
	votingDescr := "EPS-41 supervisor voting"
	answers := []string{"Veres M.M.", "Chentsov O.I."}
	whiteList := [][33]byte{{1, 2, 3}}
	votingCreationBody := transaction_specific.NewTxVotingCreation(expirationDate, votingDescr, answers, whiteList)
	txVotingCreation := transaction.NewTransaction(2, votingCreationBody)
	v.MemPool = append(v.MemPool, txVotingCreation)

	accCreationBody := transaction_specific.NewTxAccCreation(0, [33]byte{1, 2, 3})
	txAccountCreation := transaction.NewTransaction(0, accCreationBody)

	type args struct {
		transaction transaction.ITransaction
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "In MemPool",
			args: args{
				transaction: txVotingCreation,
			},
			want: true,
		},
		{
			name: "Not in MemPool",
			args: args{
				transaction: txAccountCreation,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v.isInMemPool(tt.args.transaction); got != tt.want {
				t.Errorf("isInMemPool() = %v, want %v", got, tt.want)
			}
		})
	}
}
