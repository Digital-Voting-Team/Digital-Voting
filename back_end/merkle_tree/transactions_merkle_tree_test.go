package merkle_tree

import (
	"crypto/sha256"
	"digital-voting/signature/keys"
	singleSignature "digital-voting/signature/signatures/single_signature"
	"digital-voting/transaction"
	"digital-voting/transaction/transaction_specific"
	"testing"
	"time"
)

func TestVerifyContent(t *testing.T) {
	sign := singleSignature.NewECDSA()

	keyPair1, _ := keys.FromRawSeed(sha256.Sum256([]byte(time.Now().String())), sign.Curve)

	transactions := []transaction.ITransaction{}

	myTxBody := transaction_specific.NewTxAccCreation(0, keyPair1.PublicToBytes())
	myTransaction := transaction.NewTransaction(0, myTxBody)
	transactions = append(transactions, myTransaction)

	groupName := "EPS-41"
	membersPublicKeys := [][33]byte{}
	membersPublicKeys = append(membersPublicKeys, keyPair1.PublicToBytes())
	txBody1 := transaction_specific.NewTxGroupCreation(groupName, membersPublicKeys...)
	transaction1 := transaction.NewTransaction(1, txBody1)
	transactions = append(transactions, transaction1)

	expirationDate := time.Now()
	votingDescr := "EPS-41 supervisor voting"
	answers := []string{"Veres M.M.", "Chentsov O.I."}
	whiteList := [][33]byte{{1, 2, 3}}
	txBody2 := transaction_specific.NewTxVotingCreation(expirationDate, votingDescr, answers, whiteList)
	transaction2 := transaction.NewTransaction(2, txBody2)
	transactions = append(transactions, transaction2)

	myTxBody1 := transaction_specific.NewTxAccCreation(1, keyPair1.PublicToBytes())
	myTransaction1 := transaction.NewTransaction(0, myTxBody1)

	type args struct {
		transaction     transaction.ITransaction
		transactionList []transaction.ITransaction
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
