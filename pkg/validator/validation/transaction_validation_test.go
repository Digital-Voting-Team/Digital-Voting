package validation

import (
	tx "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction"
	ts "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction/transaction_specific"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/models/account"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/curve"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
	ss "github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/signatures/single_signature"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signer"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository/account_manager"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository/indexed_groups"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository/indexed_votings"
	"log"
	"testing"
	"time"
)

func TestValidateTransaction(t *testing.T) {
	sign := ss.NewECDSA()
	txSigner := signer.NewTransactionSigner()
	indexedData := repository.NewIndexedData()

	keyPair1, _ := keys.Random(sign.Curve)
	indexedData.AccountManager.AddPubKey(keyPair1.PublicToBytes(), account_manager.RegistrationAdmin)
	indexedData.AccountManager.AddPubKey(keyPair1.PublicToBytes(), account_manager.VotingCreationAdmin)
	indexedData.AccountManager.AddPubKey(keyPair1.PublicToBytes(), account_manager.User)

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

	castedTxGrpCreationBody := txGroupCreation.TxBody.(*ts.TxGroupCreation)
	indexedData.GroupManager.AddNewGroup(indexed_groups.GroupDTO{
		GroupIdentifier:   castedTxGrpCreationBody.GroupIdentifier,
		GroupName:         castedTxGrpCreationBody.GroupName,
		MembersPublicKeys: castedTxGrpCreationBody.MembersPublicKeys,
	})

	expirationDate := time.Now().Add(time.Second * 10)
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
		indexedData.AccountManager.AddPubKey(publicBytes, account_manager.User)
		whiteList = append(whiteList, publicBytes)
	}

	votingCreationBody := ts.NewTxVotingCreation(expirationDate, votingDescr, answers, whiteList)
	txVotingCreation := tx.NewTransaction(tx.VotingCreation, votingCreationBody)
	txSigner.SignTransaction(keyPair1, txVotingCreation)

	castedTxVotingCreationBody := txVotingCreation.TxBody.(*ts.TxVotingCreation)
	indexedData.VotingManager.AddNewVoting(*indexed_votings.NewVotingDTO(
		txGroupCreation.GetHash(),
		castedTxVotingCreationBody.ExpirationDate,
		castedTxVotingCreationBody.VotingDescription,
		castedTxVotingCreationBody.Answers,
		castedTxVotingCreationBody.Whitelist,
	))

	voteBody := ts.NewTxVote(txGroupCreation.GetHash(), 0)
	txVote := tx.NewTransaction(tx.Vote, voteBody)
	txSigner.SignTransaction(keyPair1, txVote)

	txVoteAnonymous := ts.NewTxVoteAnonymous(txGroupCreation.GetHash(), 1)
	txSigner.SignTransactionAnonymous(keyPair1, publicKeys, 0, txVoteAnonymous)

	type args struct {
		tx          tx.ITransaction
		indexedData *repository.IndexedData
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Valid Account creation tx",
			args: args{
				tx:          txAccountCreation,
				indexedData: indexedData,
			},
			want: true,
		},
		{
			name: "Valid Group creation tx",
			args: args{
				tx:          txGroupCreation,
				indexedData: indexedData,
			},
			want: true,
		},
		{
			name: "Valid Voting creation tx",
			args: args{
				tx:          txVotingCreation,
				indexedData: indexedData,
			},
			want: true,
		},
		{
			name: "Valid Vote tx",
			args: args{
				tx:          txVote,
				indexedData: indexedData,
			},
			want: true,
		},
		{
			name: "Valid Vote anonymous tx",
			args: args{
				tx:          txVoteAnonymous,
				indexedData: indexedData,
			},
			want: true,
		},
		{
			name: "Invalid identity provider and/or administrator",
			args: args{
				tx:          txVoteAnonymous,
				indexedData: repository.NewIndexedData(),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckOnCreateTransaction(tt.args.tx, tt.args.indexedData); got != tt.want {
				t.Errorf("CheckOnCreateTransaction() = %v, want %v", got, tt.want)
			}
		})
	}
}
