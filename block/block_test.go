package block

import (
	"math/big"
	"testing"
	"time"
)

func TestBlock(t *testing.T) {
	b := Block{
		Header: Header{
			Version:    1,
			Previous:   &big.Int{},
			TimeStamp:  uint64(time.Unix(500, 10).Unix()),
			MerkleRoot: &big.Int{},
		},
		Witness: Witness{
			ValidatorsPublicKeys: nil,
			ValidatorsSignatures: nil,
		},
		Body: Body{
			Transactions: nil,
		},
	}

	expect := "ab6VvgItTKfL7E3Dv82EqUkREzzoE2aqYVxuK8U0_-Y="

	got := b.GetHash()
	if got != expect {
		t.Errorf("Got %s, instead of %s", got, expect)
	}

	var key = [33]byte{1, 2, 4, 41, 23}
	var signature = [33]byte{6, 12, 9, 4, 3}

	b.Sign(key, signature)

	got = b.GetHash()
	if got != expect {
		t.Errorf("Got %s, instead of %s", got, expect)
	}
}
