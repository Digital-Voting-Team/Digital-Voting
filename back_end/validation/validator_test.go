package validation

import (
	"crypto/sha256"
	"digital-voting/account"
	"digital-voting/block"
	"digital-voting/identity_provider"
	"digital-voting/signature/keys"
	singleSignature "digital-voting/signature/signatures/single_signature"
	"digital-voting/signer"
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
	txGroupCreation := transaction.NewTransaction(transaction.GroupCreation, grpCreationBody)
	v.MemPool = append(v.MemPool, txGroupCreation)

	expirationDate := time.Now()
	votingDescr := "EPS-41 supervisor voting"
	answers := []string{"Veres M.M.", "Chentsov O.I."}
	whiteList := [][33]byte{{1, 2, 3}}
	votingCreationBody := transaction_specific.NewTxVotingCreation(expirationDate, votingDescr, answers, whiteList)
	txVotingCreation := transaction.NewTransaction(transaction.VotingCreation, votingCreationBody)
	v.MemPool = append(v.MemPool, txVotingCreation)

	accCreationBody := transaction_specific.NewTxAccCreation(account.RegistrationAdmin, [33]byte{1, 2, 3})
	txAccountCreation := transaction.NewTransaction(transaction.AccountCreation, accCreationBody)

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

func TestCreateBlock(t *testing.T) {
	sign := singleSignature.NewECDSA()
	txSigner := signer.NewTransactionSigner()
	identityProvider := identity_provider.NewIdentityProvider()
	keyPair1, _ := keys.FromRawSeed(sha256.Sum256([]byte(time.Now().String())), sign.Curve)

	identityProvider.AddPubKey(keyPair1.PublicToBytes(), identity_provider.User)
	identityProvider.AddPubKey(keyPair1.PublicToBytes(), identity_provider.VotingCreationAdmin)
	identityProvider.AddPubKey(keyPair1.PublicToBytes(), identity_provider.RegistrationAdmin)

	keyPair2, _ := keys.FromRawSeed(sha256.Sum256([]byte(time.Now().String())), sign.Curve)
	accCreationBody := transaction_specific.NewTxAccCreation(account.RegistrationAdmin, keyPair2.PublicToBytes())
	txAccountCreation := transaction.NewTransaction(transaction.AccountCreation, accCreationBody)
	txSigner.SignTransaction(keyPair1, txAccountCreation)

	groupName := "EPS-41"
	membersPublicKeys := [][33]byte{}
	membersPublicKeys = append(membersPublicKeys, keyPair1.PublicToBytes())
	grpCreationBody := transaction_specific.NewTxGroupCreation(groupName, membersPublicKeys...)
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

	validator := &Validator{
		KeyPair:          keyPair1,
		IdentityProvider: identityProvider,
		BlockSigner:      signer.NewBlockSigner(),
	}
	validator.AddToMemPool(txAccountCreation)
	validator.AddToMemPool(txGroupCreation)
	validator.AddToMemPool(txVotingCreation)
	validator.AddToMemPool(txVote)

	newBlock := validator.CreateBlock([32]byte{})

	type args struct {
		previousBlockHash [32]byte
	}
	tests := []struct {
		name string
		args args
		want *block.Block
	}{
		{
			name: "Correct block",
			args: args{
				previousBlockHash: [32]byte{},
			},
			want: newBlock,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validator.CreateBlock(tt.args.previousBlockHash); got.GetHash() != tt.want.GetHash() {
				t.Errorf("CreateBlock() = %v, want %v", got, tt.want)
			}
		})
	}
}
