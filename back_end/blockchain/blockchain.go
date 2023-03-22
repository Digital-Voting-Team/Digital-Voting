package blockchain

import "digital-voting/block"

type Blockchain struct {
	Blocks []*block.Block
}

func (b *Blockchain) AddBlock(block *block.Block) {
	b.Blocks = append(b.Blocks, block)
}
