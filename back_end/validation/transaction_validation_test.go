package validation

import (
	"digital-voting/account"
	nd "digital-voting/node"
	"digital-voting/node/account_manager"
	"digital-voting/node/indexed_data"
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
	node := nd.NewNode()

	keyPair1, _ := keys.Random(sign.Curve)
	node.AccountManager.AddPubKey(keyPair1.PublicToBytes(), account_manager.RegistrationAdmin)
	node.AccountManager.AddPubKey(keyPair1.PublicToBytes(), account_manager.VotingCreationAdmin)
	node.AccountManager.AddPubKey(keyPair1.PublicToBytes(), account_manager.User)

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

	castedTxGrpCreationBody := txGroupCreation.TxBody.(*transaction_specific.TxGroupCreation)
	node.GroupProvider.AddNewGroup(indexed_data.GroupDTO{
		GroupIdentifier:   castedTxGrpCreationBody.GroupIdentifier,
		GroupName:         castedTxGrpCreationBody.GroupName,
		MembersPublicKeys: castedTxGrpCreationBody.MembersPublicKeys,
	})

	expirationDate := time.Now()
	votingDescr := "EPS-41 supervisor voting"
	answers := []string{"Veres M.M.", "Chentsov O.I."}
	whiteList := [][33]byte{keyPair1.PublicToBytes()}

	var publicKeys []*curve.Point
	publicKeys = append(publicKeys, keyPair1.GetPublicKey())
	for i := 0; i < 5; i++ {
		tempKeyPair, err := keys.Random(sign.Curve)
		if err != nil {
			log.Panicln(err)
		}
		publicKeys = append(publicKeys, tempKeyPair.GetPublicKey())
		publicBytes := tempKeyPair.PublicToBytes()
		node.AccountManager.AddPubKey(publicBytes, account_manager.User)
		whiteList = append(whiteList, publicBytes)
	}

	votingCreationBody := transaction_specific.NewTxVotingCreation(expirationDate, votingDescr, answers, whiteList)
	txVotingCreation := transaction.NewTransaction(transaction.VotingCreation, votingCreationBody)
	txSigner.SignTransaction(keyPair1, txVotingCreation)

	castedTxVotingCreationBody := txVotingCreation.TxBody.(*transaction_specific.TxVotingCreation)
	node.VotingProvider.AddNewVoting(indexed_data.VotingDTO{
		Hash:              txGroupCreation.GetHash(),
		ExpirationDate:    castedTxVotingCreationBody.ExpirationDate,
		VotingDescription: castedTxVotingCreationBody.VotingDescription,
		Answers:           castedTxVotingCreationBody.Answers,
		Whitelist:         castedTxVotingCreationBody.Whitelist,
	})

	voteBody := transaction_specific.NewTxVote(txGroupCreation.GetHash(), 0)
	txVote := transaction.NewTransaction(transaction.Vote, voteBody)
	txSigner.SignTransaction(keyPair1, txVote)

	txVoteAnonymous := transaction_specific.NewTxVoteAnonymous(txGroupCreation.GetHash(), 1)
	txSigner.SignTransactionAnonymous(keyPair1, publicKeys, 0, txVoteAnonymous)

	type args struct {
		tx   transaction.ITransaction
		node *nd.Node
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Valid Account creation transaction",
			args: args{
				tx:   txAccountCreation,
				node: node,
			},
			want: true,
		},
		{
			name: "Valid Group creation transaction",
			args: args{
				tx:   txGroupCreation,
				node: node,
			},
			want: true,
		},
		{
			name: "Valid Voting creation transaction",
			args: args{
				tx:   txVotingCreation,
				node: node,
			},
			want: true,
		},
		{
			name: "Valid Vote transaction",
			args: args{
				tx:   txVote,
				node: node,
			},
			want: true,
		},
		{
			name: "Valid Vote anonymous transaction",
			args: args{
				tx:   txVoteAnonymous,
				node: node,
			},
			want: true,
		},
		{
			name: "Invalid identity provider and/or administrator",
			args: args{
				tx:   txVoteAnonymous,
				node: nd.NewNode(),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckOnCreateTransaction(tt.args.tx, tt.args.node); got != tt.want {
				t.Errorf("CheckOnCreateTransaction() = %v, want %v", got, tt.want)
			}
		})
	}
}
