package blockchain

import (
	"digital-voting/block"
	"fmt"
)

// Blockchain TODO: create class Node with Blockchain and indexed databases
type Blockchain struct {
	Blocks []*block.Block
}

func (b *Blockchain) AddBlock(block *block.Block) {
	b.Blocks = append(b.Blocks, block)
}

func (b *Blockchain) GetBlock(hash [32]byte) (*block.Block, error) {
	for _, current := range b.Blocks {
		if current.GetHash() == hash {
			return current, nil
		}
	}

	return nil, fmt.Errorf("block with given hash was not found")
}
