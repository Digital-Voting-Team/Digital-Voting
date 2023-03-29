package validation

import (
	"digital-voting/account"
	blk "digital-voting/block"
	ip "digital-voting/identity_provider"
	"digital-voting/signature/keys"
	singleSignature "digital-voting/signature/signatures/single_signature"
	"digital-voting/signer"
	tx "digital-voting/transaction"
	tx_specific "digital-voting/transaction/transaction_specific"
	"testing"
	"time"
)

func TestIsInMemPool(t *testing.T) {
	v := &Validator{}

	groupName := "EPS-41"
	membersPublicKeys := []keys.PublicKeyBytes{}
	membersPublicKeys = append(membersPublicKeys, keys.PublicKeyBytes{1, 2, 3})
	grpCreationBody := tx_specific.NewTxGroupCreation(groupName, membersPublicKeys...)
	txGroupCreation := tx.NewTransaction(tx.GroupCreation, grpCreationBody)
	v.MemPool = append(v.MemPool, txGroupCreation)

	expirationDate := time.Now()
	votingDescr := "EPS-41 supervisor voting"
	answers := []string{"Veres M.M.", "Chentsov O.I."}
	whiteList := [][33]byte{{1, 2, 3}}
	votingCreationBody := tx_specific.NewTxVotingCreation(expirationDate, votingDescr, answers, whiteList)
	txVotingCreation := tx.NewTransaction(tx.VotingCreation, votingCreationBody)
	v.MemPool = append(v.MemPool, txVotingCreation)

	accCreationBody := tx_specific.NewTxAccCreation(account.RegistrationAdmin, keys.PublicKeyBytes{1, 2, 3})
	txAccountCreation := tx.NewTransaction(tx.AccountCreation, accCreationBody)

	type args struct {
		transaction tx.ITransaction
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
	identityProvider := ip.NewIdentityProvider()
	keyPair1, _ := keys.Random(sign.Curve)

	identityProvider.AddPubKey(keyPair1.PublicToBytes(), ip.User)
	identityProvider.AddPubKey(keyPair1.PublicToBytes(), ip.VotingCreationAdmin)
	identityProvider.AddPubKey(keyPair1.PublicToBytes(), ip.RegistrationAdmin)

	keyPair2, _ := keys.Random(sign.Curve)
	accCreationBody := tx_specific.NewTxAccCreation(account.RegistrationAdmin, keyPair2.PublicToBytes())
	txAccountCreation := tx.NewTransaction(tx.AccountCreation, accCreationBody)
	txSigner.SignTransaction(keyPair1, txAccountCreation)

	groupName := "EPS-41"
	membersPublicKeys := []keys.PublicKeyBytes{}
	membersPublicKeys = append(membersPublicKeys, keyPair1.PublicToBytes())
	grpCreationBody := tx_specific.NewTxGroupCreation(groupName, membersPublicKeys...)
	txGroupCreation := tx.NewTransaction(tx.GroupCreation, grpCreationBody)
	txSigner.SignTransaction(keyPair1, txGroupCreation)

	expirationDate := time.Now()
	votingDescr := "EPS-41 supervisor voting"
	answers := []string{"Veres M.M.", "Chentsov O.I."}
	whiteList := [][33]byte{keyPair1.PublicToBytes()}
	votingCreationBody := tx_specific.NewTxVotingCreation(expirationDate, votingDescr, answers, whiteList)
	txVotingCreation := tx.NewTransaction(tx.VotingCreation, votingCreationBody)
	txSigner.SignTransaction(keyPair1, txVotingCreation)

	voteBody := tx_specific.NewTxVote([32]byte{}, 0)
	txVote := tx.NewTransaction(tx.Vote, voteBody)
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
		want *blk.Block
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

func TestActualizeIdentityProvider(t *testing.T) {
	sign := singleSignature.NewECDSA()
	identityProvider := ip.NewIdentityProvider()

	validatorKeyPair, _ := keys.Random(sign.Curve)
	identityProvider.AddPubKey(validatorKeyPair.PublicToBytes(), ip.Validator)

	validator := &Validator{
		KeyPair:          validatorKeyPair,
		IdentityProvider: identityProvider,
		BlockSigner:      signer.NewBlockSigner(),
	}

	adminKeyPair, _ := keys.Random(sign.Curve)
	identityProvider.AddPubKey(adminKeyPair.PublicToBytes(), ip.RegistrationAdmin)

	userKeyPair, _ := keys.Random(sign.Curve)
	transaction := tx.NewTransaction(tx.AccountCreation, tx_specific.NewTxAccCreation(account.User, userKeyPair.PublicToBytes()))
	userKeyPairFake, _ := keys.Random(sign.Curve)

	txSigner := signer.NewTransactionSigner()
	txSigner.SignTransaction(adminKeyPair, transaction)

	validator.AddToMemPool(transaction)
	block := validator.CreateBlock([32]byte{})

	validator.ActualizeIdentityProvider(block)

	type args struct {
		publicKey keys.PublicKeyBytes
		keyType   ip.Identifier
	}
	tests := []struct {
		name     string
		args     args
		wantBool bool
	}{
		{
			name: "New account added to identity provider",
			args: args{
				publicKey: userKeyPair.PublicToBytes(),
				keyType:   ip.User,
			},
			wantBool: true,
		},
		{
			name: "Account wasn't added to identity provider",
			args: args{
				publicKey: userKeyPairFake.PublicToBytes(),
				keyType:   ip.User,
			},
			wantBool: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := identityProvider.CheckPubKeyPresence(tt.args.publicKey, tt.args.keyType); got != tt.wantBool {
				t.Errorf("Is new identifier in identity provider: %v, should it be there: %v", got, tt.wantBool)
			}
		})
	}
}
