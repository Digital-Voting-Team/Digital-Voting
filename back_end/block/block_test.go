package block

import (
	"digital-voting/signature/keys"
	signatures "digital-voting/signature/signatures/single_signature"
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
	var signature = signatures.SingleSignatureBytes{6, 12, 9, 4, 3}

	b.Sign(key, signature)

	got = b.GetHashString()
	if got != expect {
		t.Errorf("Got %s, instead of %s", got, expect)
	}
}
