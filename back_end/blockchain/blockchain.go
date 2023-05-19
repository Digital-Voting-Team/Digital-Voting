package blockchain

import (
	"digital-voting/block"
	"fmt"
)

type Blockchain struct {
	Blocks []*block.Block
}

func (b *Blockchain) AddBlock(block *block.Block) error {
	if block == nil {
		return fmt.Errorf("block is nil")
	}

	b.Blocks = append(b.Blocks, block)

	return nil
}

func (b *Blockchain) GetBlock(hash [32]byte) (*block.Block, error) {
	for _, current := range b.Blocks {
		if current.GetHash() == hash {
			return current, nil
		}
	}

	return nil, fmt.Errorf("block with given hash was not found")
}
