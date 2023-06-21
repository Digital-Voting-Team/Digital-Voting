package blockchain

import (
	"fmt"
	blk "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/block"
)

type Blockchain struct {
	Blocks []*blk.Block
}

func (b *Blockchain) AddBlock(block *blk.Block) error {
	if block == nil {
		return fmt.Errorf("blk is nil")
	}

	b.Blocks = append(b.Blocks, block)

	return nil
}

func (b *Blockchain) GetBlock(hash [32]byte) (*blk.Block, error) {
	for _, current := range b.Blocks {
		if current.GetHash() == hash {
			return current, nil
		}
	}

	return nil, fmt.Errorf("blk with given hash was not found")
}

// GetLastBlockHash get last blk hash
func (b *Blockchain) GetLastBlockHash() [32]byte {
	return b.Blocks[len(b.Blocks)-1].GetHash()
}
