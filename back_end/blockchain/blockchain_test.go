package blockchain

import (
	"digital-voting/block"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBlockchain_GetBlock(t *testing.T) {
	tests := []struct {
		name string
		b    *Blockchain
		hash [32]byte
		want *block.Block
		err  require.ErrorAssertionFunc
	}{
		{
			name: "empty blockchain",
			b:    &Blockchain{},
			hash: [32]byte{},
			want: nil,
			err:  require.Error,
		},
		{
			name: "blockchain with one block",
			b: &Blockchain{
				Blocks: []*block.Block{
					{},
				},
			},
			// hash of empty block
			hash: [32]byte{89, 30, 32, 250, 95, 98, 97, 139, 139, 137, 172, 12, 26, 84, 187, 91, 65, 82, 16, 79, 79, 69, 158, 210, 187, 152, 72, 222, 90, 241, 38, 213},
			want: &block.Block{},
			err:  require.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.b.GetBlock(tt.hash)
			tt.err(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestBlockchain_AddBlock(t *testing.T) {
	tests := []struct {
		block *block.Block
		name  string
		b     *Blockchain
		err   require.ErrorAssertionFunc
	}{
		{
			name:  "nil block",
			b:     &Blockchain{},
			block: nil,
			err:   require.Error,
		},
		{
			name:  "valid block",
			b:     &Blockchain{},
			block: &block.Block{},
			err:   require.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.b.AddBlock(tt.block)
			tt.err(t, err)
		})
	}
}
