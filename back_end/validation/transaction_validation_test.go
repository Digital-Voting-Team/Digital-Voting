package validation

import (
	"digital-voting/account"
	"digital-voting/identity_provider"
	"digital-voting/signature/curve"
	"digital-voting/signature/keys"
	singleSignature "digital-voting/signature/signatures/single_signature"
	"digital-voting/signer"
	"digital-voting/transaction"
	"digital-voting/transaction/transaction_specific"
	"log"
	"testing"
	"time"
)

func TestValidateTransaction(t *testing.T) {
	sign := singleSignature.NewECDSA()
	txSigner := signer.NewTransactionSigner()
	identityProvider := identity_provider.NewIdentityProvider()

	keyPair1, _ := keys.Random(sign.Curve)
	identityProvider.AddPubKey(keyPair1.PublicToBytes(), identity_provider.RegistrationAdmin)
	identityProvider.AddPubKey(keyPair1.PublicToBytes(), identity_provider.VotingCreationAdmin)
	identityProvider.AddPubKey(keyPair1.PublicToBytes(), identity_provider.User)

	keyPair2, _ := keys.Random(sign.Curve)
	accCreationBody := transaction_specific.NewTxAccCreation(account.RegistrationAdmin, keyPair2.PublicToBytes())
	txAccountCreation := transaction.NewTransaction(transaction.AccountCreation, accCreationBody)
	txSigner.SignTransaction(keyPair1, txAccountCreation)

	groupName := "EPS-41"
	membersPublicKeys := []keys.PublicKeyBytes{}
	membersPublicKeys = append(membersPublicKeys, keyPair1.PublicToBytes())
	grpCreationBody := transaction_specific.NewTxGroupCreation(groupName, membersPublicKeys)
	txGroupCreation := transaction.NewTransaction(transaction.GroupCreation, grpCreationBody)
	txSigner.SignTransaction(keyPair1, txGroupCreation)

	expirationDate := time.Now()
	votingDescr := "EPS-41 supervisor voting"
	answers := []string{"Veres M.M.", "Chentsov O.I."}
	whiteList := [][33]byte{keyPair1.PublicToBytes()}
	votingCreationBody := transaction_specific.NewTxVotingCreation(expirationDate, votingDescr, answers, whiteList)
	txVotingCreation := transaction.NewTransaction(transaction.VotingCreation, votingCreationBody)
	txSigner.SignTransaction(keyPair1, txVotingCreation)

	voteBody := transaction_specific.NewTxVote([32]byte{}, 0)
	txVote := transaction.NewTransaction(transaction.Vote, voteBody)
	txSigner.SignTransaction(keyPair1, txVote)

	var publicKeys []*curve.Point
	publicKeys = append(publicKeys, keyPair1.GetPublicKey())
	for i := 0; i < 5; i++ {
		tempKeyPair, err := keys.Random(sign.Curve)
		if err != nil {
			log.Panicln(err)
		}
		publicKeys = append(publicKeys, tempKeyPair.GetPublicKey())
		identityProvider.AddPubKey(tempKeyPair.PublicToBytes(), identity_provider.User)
	}
	txVoteAnonymous := transaction_specific.NewTxVoteAnonymous([32]byte{}, 3)
	txSigner.SignTransactionAnonymous(keyPair1, publicKeys, 0, txVoteAnonymous)

	type args struct {
		tx               transaction.ITransaction
		identityProvider *identity_provider.IdentityProvider
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Valid Account creation transaction",
			args: args{
				tx:               txAccountCreation,
				identityProvider: identityProvider,
			},
			want: true,
		},
		{
			name: "Valid Group creation transaction",
			args: args{
				tx:               txGroupCreation,
				identityProvider: identityProvider,
			},
			want: true,
		},
		{
			name: "Valid Voting creation transaction",
			args: args{
				tx:               txVotingCreation,
				identityProvider: identityProvider,
			},
			want: true,
		},
		{
			name: "Valid Vote transaction",
			args: args{
				tx:               txVote,
				identityProvider: identityProvider,
			},
			want: true,
		},
		{
			name: "Valid Vote anonymous transaction",
			args: args{
				tx:               txVoteAnonymous,
				identityProvider: identityProvider,
			},
			want: true,
		},
		{
			name: "Invalid identity provider and/or administrator",
			args: args{
				tx:               txVoteAnonymous,
				identityProvider: identity_provider.NewIdentityProvider(),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateTransaction(tt.args.tx, tt.args.identityProvider); got != tt.want {
				t.Errorf("ValidateTransaction() = %v, want %v", got, tt.want)
			}
		})
	}
}
