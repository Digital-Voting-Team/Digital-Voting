package transaction_json

import (
	"digital-voting/account"
	"digital-voting/signature/keys"
	ss "digital-voting/signature/signatures/single_signature"
	"digital-voting/signer"
	"digital-voting/transaction"
	"digital-voting/transaction/transaction_specific"
	"encoding/json"
	"reflect"
	"testing"
)

func TestUnmarshallJSON(t *testing.T) {
	sign := ss.NewECDSA()
	txSigner := signer.NewTransactionSigner()
	keyPair1, _ := keys.Random(sign.Curve)

	accCreationBody := transaction_specific.NewTxAccCreation(account.RegistrationAdmin, keyPair1.PublicToBytes())
	txAccountCreation := transaction.NewTransaction(transaction.AccountCreation, accCreationBody)
	txSigner.SignTransaction(keyPair1, txAccountCreation)

	marshalledAccCreation, _ := json.Marshal(txAccountCreation)

	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    transaction.ITransaction
		wantErr bool
	}{
		{
			name: "Unmarshall transaction account creation",
			args: args{
				data: marshalledAccCreation,
			},
			want:    txAccountCreation,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (&JSONTransaction{}).UnmarshallJSON(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshallJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshallJSON() got = %v, want %v", got, tt.want)
			}
		})
	}
}
