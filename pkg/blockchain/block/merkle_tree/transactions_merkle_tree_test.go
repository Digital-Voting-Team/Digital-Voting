package merkle_tree

import (
	tx "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction"
	ts "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction/transaction_specific"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/models/account"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
	ss "github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/signatures/single_signature"
	"testing"
	"time"
)

func TestVerifyContent(t *testing.T) {
	sign := ss.NewECDSA()

	keyPair1, _ := keys.Random(sign.Curve)

	transactions := []tx.ITransaction{}

	myTxBody := ts.NewTxAccCreation(account.RegistrationAdmin, keyPair1.PublicToBytes())
	myTransaction := tx.NewTransaction(tx.AccountCreation, myTxBody)
	transactions = append(transactions, myTransaction)

	groupName := "EPS-41"
	membersPublicKeys := []keys.PublicKeyBytes{}
	membersPublicKeys = append(membersPublicKeys, keyPair1.PublicToBytes())
	txBody1 := ts.NewTxGroupCreation(groupName, membersPublicKeys)
	transaction1 := tx.NewTransaction(tx.GroupCreation, txBody1)
	transactions = append(transactions, transaction1)

	expirationDate := time.Now()
	votingDescr := "EPS-41 supervisor voting"
	answers := []string{"Veres M.M.", "Chentsov O.I."}
	whiteList := [][33]byte{{1, 2, 3}}
	txBody2 := ts.NewTxVotingCreation(expirationDate, votingDescr, answers, whiteList)
	transaction2 := tx.NewTransaction(tx.VotingCreation, txBody2)
	transactions = append(transactions, transaction2)

	myTxBody1 := ts.NewTxAccCreation(account.VotingCreationAdmin, keyPair1.PublicToBytes())
	myTransaction1 := tx.NewTransaction(tx.AccountCreation, myTxBody1)

	type args struct {
		transaction     tx.ITransaction
		transactionList []tx.ITransaction
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Transaction is present",
			args: args{
				transaction:     myTransaction,
				transactionList: transactions,
			},
			want: true,
		},
		{
			name: "Transaction is not present",
			args: args{
				transaction:     myTransaction1,
				transactionList: transactions,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyContent(tt.args.transaction, tt.args.transactionList); got != tt.want {
				t.Errorf("VerifyContent() = %v, want %v", got, tt.want)
			}
		})
	}
}
