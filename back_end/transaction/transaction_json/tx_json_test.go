package transaction_json

import (
	"digital-voting/account"
	"digital-voting/signature/keys"
	ss "digital-voting/signature/signatures/single_signature"
	"digital-voting/transaction"
	"digital-voting/transaction/transaction_specific"
	"reflect"
	"testing"
)

func TestUnmarshallJSON(t *testing.T) {
	marshalledTransaction := []byte(
		`{
			"tx_type": 0,
			"tx_body": {
				"account_type": 0,
				"new_public_key": [
					1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33
				]
			},
			"nonce": 1,
			"signature": [
				131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194
			],
			"public_key": [
				65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97
			]
		  }`)

	wantTransaction := &transaction.Transaction{
		TxType: transaction.AccountCreation,
		TxBody: &transaction_specific.TxAccountCreation{
			AccountType:  account.User,
			NewPublicKey: keys.PublicKeyBytes{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33},
		},
		Nonce:     1,
		Signature: ss.SingleSignatureBytes{131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194},
		PublicKey: keys.PublicKeyBytes{65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97},
	}

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
				data: marshalledTransaction,
			},
			want:    wantTransaction,
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
