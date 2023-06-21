package block

import (
	tx "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction"
	ts "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction/transaction_specific"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/models/account"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
	ss "github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/signatures/single_signature"
	"reflect"
	"testing"
	"time"
)

func TestBlock(t *testing.T) {
	b := Block{
		Header: Header{
			Version:    1,
			Previous:   [32]byte{1, 4, 5, 6, 7, 46},
			TimeStamp:  uint64(time.Unix(500, 10).Unix()),
			MerkleRoot: [32]byte{1, 4, 5, 6, 7, 46},
		},
		Witness: Witness{
			ValidatorsPublicKeys: nil,
			ValidatorsSignatures: nil,
		},
		Body: Body{
			Transactions: nil,
		},
	}

	expect := "qRe34zCgwa9scJCoZTFJx0_lg9kS2NC_qw4_BwbiNt8="

	got := b.GetHashString()
	if got != expect {
		t.Errorf("Got %s, instead of %s", got, expect)
	}

	var key = keys.PublicKeyBytes{1, 2, 4, 41, 23}
	var signature = ss.SingleSignatureBytes{6, 12, 9, 4, 3}

	b.Sign(key, signature)

	got = b.GetHashString()
	if got != expect {
		t.Errorf("Got %s, instead of %s", got, expect)
	}
}

func TestUnmarshallBlock(t *testing.T) {
	marshalledBlock := []byte(
		`{
		  "header": {
			"version": 1,
			"previous": [
			  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
			],
			"time_stamp": 1621617400,
			"merkle_root": [
			  33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64
			]
		  },
		  "witness": {
			"public_keys": [
			  [
				65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97
			  ],
			  [
				98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130
			  ]
			],
			"signatures": [
			  [
				131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194
			  ],
			  [
				200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,0,1,2,3,4,5,6,7,8
			  ]
			]
		  },
		  "body": {
			"transactions": [
			  {
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
			  }
			]
		  }
		}`)

	wantBlock := &Block{
		Header: Header{
			Version:    1,
			Previous:   [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
			TimeStamp:  1621617400,
			MerkleRoot: [32]byte{33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64},
		},
		Witness: Witness{
			ValidatorsPublicKeys: []keys.PublicKeyBytes{
				{65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97},
				{98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130},
			},
			ValidatorsSignatures: []ss.SingleSignatureBytes{
				{131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194},
				{200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8},
			},
		},
		Body: Body{
			Transactions: []tx.ITransaction{
				&tx.Transaction{
					TxType: tx.AccountCreation,
					TxBody: &ts.TxAccountCreation{
						AccountType:  account.User,
						NewPublicKey: keys.PublicKeyBytes{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33},
					},
					Nonce:     1,
					Signature: ss.SingleSignatureBytes{131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194},
					PublicKey: keys.PublicKeyBytes{65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97},
				},
			},
		},
	}
	type args struct {
		marshalledBlock []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *Block
		wantErr bool
	}{
		{
			name: "Unmarshall valid block in JSON representation",
			args: args{
				marshalledBlock: marshalledBlock,
			},
			want:    wantBlock,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshallBlock(tt.args.marshalledBlock)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshallBlock() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshallBlock() got = %v, want %v", got, tt.want)
			}
		})
	}
}
