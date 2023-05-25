package validation

import (
	"digital-voting/account"
	blk "digital-voting/block"
	"digital-voting/blockchain"
	"digital-voting/merkle_tree"
	nd "digital-voting/node"
	ip "digital-voting/node/account_manager"
	"digital-voting/signature/keys"
	singleSignature "digital-voting/signature/signatures/single_signature"
	"digital-voting/signer"
	tx "digital-voting/transaction"
	tx_specific "digital-voting/transaction/transaction_specific"
	"testing"
	"time"
)

func TestIsInMemPool(t *testing.T) {
	v := &Validator{MemPool: NewMemPool(), Node: nd.NewNode()}

	groupName := "EPS-41"
	membersPublicKeys := []keys.PublicKeyBytes{}
	membersPublicKeys = append(membersPublicKeys, keys.PublicKeyBytes{1, 2, 3})
	grpCreationBody := tx_specific.NewTxGroupCreation(groupName, membersPublicKeys)
	txGroupCreation := tx.NewTransaction(tx.GroupCreation, grpCreationBody)
	v.MemPool.AddToMemPool(txGroupCreation, v.Node)

	expirationDate := time.Now()
	votingDescr := "EPS-41 supervisor voting"
	answers := []string{"Veres M.M.", "Chentsov O.I."}
	whiteList := [][33]byte{{1, 2, 3}}
	votingCreationBody := tx_specific.NewTxVotingCreation(expirationDate, votingDescr, answers, whiteList)
	txVotingCreation := tx.NewTransaction(tx.VotingCreation, votingCreationBody)
	v.MemPool.AddToMemPool(txVotingCreation, v.Node)

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
			want: false,
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
	sign := singleSignature.NewECDSA()
	txSigner := signer.NewTransactionSigner()
	node := nd.NewNode()
	keyPair1, _ := keys.Random(sign.Curve)

	node.AccountManager.AddPubKey(keyPair1.PublicToBytes(), ip.User)
	node.AccountManager.AddPubKey(keyPair1.PublicToBytes(), ip.VotingCreationAdmin)
	node.AccountManager.AddPubKey(keyPair1.PublicToBytes(), ip.RegistrationAdmin)

	keyPair2, _ := keys.Random(sign.Curve)
	accCreationBody := tx_specific.NewTxAccCreation(account.RegistrationAdmin, keyPair2.PublicToBytes())
	txAccountCreation := tx.NewTransaction(tx.AccountCreation, accCreationBody)
	txSigner.SignTransaction(keyPair1, txAccountCreation)

	groupName := "EPS-41"
	membersPublicKeys := []keys.PublicKeyBytes{}
	membersPublicKeys = append(membersPublicKeys, keyPair1.PublicToBytes())
	grpCreationBody := tx_specific.NewTxGroupCreation(groupName, membersPublicKeys)
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
		MemPool:     NewMemPool(),
		KeyPair:     keyPair1,
		Node:        node,
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
			name: "Correct block",
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
	sign := singleSignature.NewECDSA()
	node := nd.NewNode()

	validatorKeyPair, _ := keys.Random(sign.Curve)
	node.AccountManager.AddPubKey(validatorKeyPair.PublicToBytes(), ip.Validator)

	validator := &Validator{
		MemPool:     NewMemPool(),
		KeyPair:     validatorKeyPair,
		Node:        node,
		BlockSigner: signer.NewBlockSigner(),
	}

	adminKeyPair, _ := keys.Random(sign.Curve)
	node.AccountManager.AddPubKey(adminKeyPair.PublicToBytes(), ip.RegistrationAdmin)

	userKeyPair, _ := keys.Random(sign.Curve)
	transaction := tx.NewTransaction(tx.AccountCreation, tx_specific.NewTxAccCreation(account.User, userKeyPair.PublicToBytes()))
	userKeyPairFake, _ := keys.Random(sign.Curve)

	txSigner := signer.NewTransactionSigner()
	txSigner.SignTransaction(adminKeyPair, transaction)

	validator.AddToMemPool(transaction)

	node.AccountManager.AddPubKey(adminKeyPair.PublicToBytes(), ip.VotingCreationAdmin)
	node.AccountManager.AddPubKey(adminKeyPair.PublicToBytes(), ip.User)
	expirationDate := time.Now()
	votingDescr := "EPS-41 supervisor voting"
	answers := []string{"Veres M.M.", "Chentsov O.I."}
	whiteList := [][33]byte{adminKeyPair.PublicToBytes()}
	votingCreationBody := tx_specific.NewTxVotingCreation(expirationDate, votingDescr, answers, whiteList)
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
			if got := node.AccountManager.CheckPubKeyPresence(tt.args.publicKey, tt.args.keyType); got != tt.wantBool {
				t.Errorf("Is new identifier in identity provider: %v, should it be there: %v", got, tt.wantBool)
			}
		})
	}
}

func TestVerifyBlock(t *testing.T) {
	sign := singleSignature.NewECDSA()
	node := nd.NewNode()

	validatorKeyPair, _ := keys.Random(sign.Curve)
	node.AccountManager.AddPubKey(validatorKeyPair.PublicToBytes(), ip.Validator)

	validator := &Validator{
		MemPool:     NewMemPool(),
		KeyPair:     validatorKeyPair,
		Node:        node,
		BlockSigner: signer.NewBlockSigner(),
		Blockchain:  &blockchain.Blockchain{Blocks: []*blk.Block{{}}},
	}

	adminKeyPair, _ := keys.Random(sign.Curve)
	node.AccountManager.AddPubKey(adminKeyPair.PublicToBytes(), ip.RegistrationAdmin)
	genesisTransaction1 := tx.NewTransaction(tx.AccountCreation, tx_specific.NewTxAccCreation(account.RegistrationAdmin, adminKeyPair.PublicToBytes()))
	transactionSigner := signer.NewTransactionSigner()
	transactionSigner.SignTransaction(adminKeyPair, genesisTransaction1)
	genesisBlock := blk.NewBlock([]tx.ITransaction{genesisTransaction1}, [32]byte{89, 30, 32, 250, 95, 98, 97, 139, 139, 137, 172, 12, 26, 84, 187, 91, 65, 82, 16, 79, 79, 69, 158, 210, 187, 152, 72, 222, 90, 241, 38, 213})

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
			name: "Verify valid block",
			args: args{
				block: genesisBlock,
			},
			wantBool: true,
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
