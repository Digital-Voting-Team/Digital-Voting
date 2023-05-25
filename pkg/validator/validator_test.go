package validator

import (
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain"
	blk "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/block"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/block/merkle_tree"
	tx "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction"
	ts "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction/transaction_specific"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/models/account"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
	ss "github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/signatures/single_signature"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signer"
	nd "github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository"
	ip "github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository/account_manager"
	"testing"
	"time"
)

func TestIsInMemPool(t *testing.T) {
	v := &Validator{MemPool: NewMemPool(), Node: nd.NewIndexedData()}

	groupName := "EPS-41"
	membersPublicKeys := []keys.PublicKeyBytes{}
	membersPublicKeys = append(membersPublicKeys, keys.PublicKeyBytes{1, 2, 3})
	grpCreationBody := ts.NewTxGroupCreation(groupName, membersPublicKeys)
	txGroupCreation := tx.NewTransaction(tx.GroupCreation, grpCreationBody)
	v.MemPool.AddToMemPool(txGroupCreation)

	expirationDate := time.Now()
	votingDescr := "EPS-41 supervisor voting"
	answers := []string{"Veres M.M.", "Chentsov O.I."}
	whiteList := [][33]byte{{1, 2, 3}}
	votingCreationBody := ts.NewTxVotingCreation(expirationDate, votingDescr, answers, whiteList)
	txVotingCreation := tx.NewTransaction(tx.VotingCreation, votingCreationBody)
	v.MemPool.AddToMemPool(txVotingCreation)

	accCreationBody := ts.NewTxAccCreation(account.RegistrationAdmin, keys.PublicKeyBytes{1, 2, 3})
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
			if got := v.MemPool.IsInMemPool(tt.args.transaction); got != tt.want {
				t.Errorf("isInMemPool() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateBlock(t *testing.T) {
	sign := ss.NewECDSA()
	txSigner := signer.NewTransactionSigner()
	indexedData := nd.NewIndexedData()
	keyPair1, _ := keys.Random(sign.Curve)

	indexedData.AccountManager.AddPubKey(keyPair1.PublicToBytes(), ip.User)
	indexedData.AccountManager.AddPubKey(keyPair1.PublicToBytes(), ip.VotingCreationAdmin)
	indexedData.AccountManager.AddPubKey(keyPair1.PublicToBytes(), ip.RegistrationAdmin)

	keyPair2, _ := keys.Random(sign.Curve)
	accCreationBody := ts.NewTxAccCreation(account.RegistrationAdmin, keyPair2.PublicToBytes())
	txAccountCreation := tx.NewTransaction(tx.AccountCreation, accCreationBody)
	txSigner.SignTransaction(keyPair1, txAccountCreation)

	groupName := "EPS-41"
	membersPublicKeys := []keys.PublicKeyBytes{}
	membersPublicKeys = append(membersPublicKeys, keyPair1.PublicToBytes())
	grpCreationBody := ts.NewTxGroupCreation(groupName, membersPublicKeys)
	txGroupCreation := tx.NewTransaction(tx.GroupCreation, grpCreationBody)
	txSigner.SignTransaction(keyPair1, txGroupCreation)

	expirationDate := time.Now()
	votingDescr := "EPS-41 supervisor voting"
	answers := []string{"Veres M.M.", "Chentsov O.I."}
	whiteList := [][33]byte{keyPair1.PublicToBytes()}
	votingCreationBody := ts.NewTxVotingCreation(expirationDate, votingDescr, answers, whiteList)
	txVotingCreation := tx.NewTransaction(tx.VotingCreation, votingCreationBody)
	txSigner.SignTransaction(keyPair1, txVotingCreation)

	voteBody := ts.NewTxVote([32]byte{}, 0)
	txVote := tx.NewTransaction(tx.Vote, voteBody)
	txSigner.SignTransaction(keyPair1, txVote)

	validator := &Validator{
		MemPool:     NewMemPool(),
		KeyPair:     keyPair1,
		Node:        indexedData,
		BlockSigner: signer.NewBlockSigner(),
	}
	validator.AddToMemPool(txAccountCreation)
	validator.AddToMemPool(txGroupCreation)
	validator.AddToMemPool(txVotingCreation)
	validator.AddToMemPool(txVote)

	blockBody := blk.Body{
		Transactions: validator.MemPool.Transactions,
	}
	timeStamp := uint64(time.Unix(1494505756, 0).Unix())
	blockHeader := blk.Header{
		Previous:   [32]byte{},
		TimeStamp:  timeStamp,
		MerkleRoot: merkle_tree.GetMerkleRoot(blockBody.Transactions),
	}
	testBlock := &blk.Block{
		Header: blockHeader,
		Body:   blockBody,
	}
	validator.SignAndUpdateBlock(testBlock)

	type args struct {
		previousBlockHash [32]byte
	}
	tests := []struct {
		name string
		args args
		want *blk.Block
	}{
		{
			name: "Correct blk",
			args: args{
				previousBlockHash: [32]byte{},
			},
			want: testBlock,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validator.CreateBlock(tt.args.previousBlockHash)
			got.Witness.ValidatorsPublicKeys = tt.want.Witness.ValidatorsPublicKeys
			got.Witness.ValidatorsSignatures = tt.want.Witness.ValidatorsSignatures
			got.Header.TimeStamp = timeStamp
			if got.GetHash() != tt.want.GetHash() {
				t.Errorf("CreateBlock() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestActualizeIdentityProvider(t *testing.T) {
	sign := ss.NewECDSA()
	indexedData := nd.NewIndexedData()

	validatorKeyPair, _ := keys.Random(sign.Curve)
	indexedData.AccountManager.AddPubKey(validatorKeyPair.PublicToBytes(), ip.Validator)

	validator := &Validator{
		MemPool:     NewMemPool(),
		KeyPair:     validatorKeyPair,
		Node:        indexedData,
		BlockSigner: signer.NewBlockSigner(),
	}

	adminKeyPair, _ := keys.Random(sign.Curve)
	indexedData.AccountManager.AddPubKey(adminKeyPair.PublicToBytes(), ip.RegistrationAdmin)

	userKeyPair, _ := keys.Random(sign.Curve)
	transaction := tx.NewTransaction(tx.AccountCreation, ts.NewTxAccCreation(account.User, userKeyPair.PublicToBytes()))
	userKeyPairFake, _ := keys.Random(sign.Curve)

	txSigner := signer.NewTransactionSigner()
	txSigner.SignTransaction(adminKeyPair, transaction)

	validator.AddToMemPool(transaction)

	indexedData.AccountManager.AddPubKey(adminKeyPair.PublicToBytes(), ip.VotingCreationAdmin)
	indexedData.AccountManager.AddPubKey(adminKeyPair.PublicToBytes(), ip.User)
	expirationDate := time.Now()
	votingDescr := "EPS-41 supervisor voting"
	answers := []string{"Veres M.M.", "Chentsov O.I."}
	whiteList := [][33]byte{adminKeyPair.PublicToBytes()}
	votingCreationBody := ts.NewTxVotingCreation(expirationDate, votingDescr, answers, whiteList)
	txVotingCreation := tx.NewTransaction(tx.VotingCreation, votingCreationBody)
	txSigner.SignTransaction(adminKeyPair, txVotingCreation)

	validator.AddToMemPool(txVotingCreation)

	block := validator.CreateBlock([32]byte{})

	validator.ActualizeNodeData(block)

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
			if got := indexedData.AccountManager.CheckPubKeyPresence(tt.args.publicKey, tt.args.keyType); got != tt.wantBool {
				t.Errorf("Is new identifier in identity provider: %v, should it be there: %v", got, tt.wantBool)
			}
		})
	}
}

func TestVerifyBlock(t *testing.T) {
	sign := ss.NewECDSA()
	indexedData := nd.NewIndexedData()

	validatorKeyPair, _ := keys.Random(sign.Curve)
	indexedData.AccountManager.AddPubKey(validatorKeyPair.PublicToBytes(), ip.Validator)

	validator := &Validator{
		MemPool:     NewMemPool(),
		KeyPair:     validatorKeyPair,
		Node:        indexedData,
		BlockSigner: signer.NewBlockSigner(),
		Blockchain:  &blockchain.Blockchain{Blocks: []*blk.Block{{}}},
	}

	adminKeyPair, _ := keys.Random(sign.Curve)
	indexedData.AccountManager.AddPubKey(adminKeyPair.PublicToBytes(), ip.RegistrationAdmin)
	genesisTransaction1 := tx.NewTransaction(tx.AccountCreation, ts.NewTxAccCreation(account.RegistrationAdmin, adminKeyPair.PublicToBytes()))
	transactionSigner := signer.NewTransactionSigner()
	transactionSigner.SignTransaction(adminKeyPair, genesisTransaction1)
	genesisBlock := blk.NewBlock([]tx.ITransaction{genesisTransaction1}, [32]byte{89, 30, 32, 250, 95, 98, 97, 139, 139, 137, 172, 12, 26, 84, 187, 91, 65, 82, 16, 79, 79, 69, 158, 210, 187, 152, 72, 222, 90, 241, 38, 213})
	fakeBlock := blk.NewBlock([]tx.ITransaction{genesisTransaction1}, [32]byte{})

	validator.SignAndUpdateBlock(genesisBlock)

	type args struct {
		block *blk.Block
	}
	tests := []struct {
		name     string
		args     args
		wantBool bool
	}{
		{
			name: "Verify valid blk",
			args: args{
				block: genesisBlock,
			},
			wantBool: true,
		},
		{
			name: "Verify bot valid blk",
			args: args{
				block: fakeBlock,
			},
			wantBool: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validator.VerifyBlock(tt.args.block); got != tt.wantBool {
				t.Errorf("VerifyBlock function returned: %v, expected value was: %v", got, tt.wantBool)
			}
		})
	}
}
