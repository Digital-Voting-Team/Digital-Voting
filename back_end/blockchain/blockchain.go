package blockchain

import "digital-voting/block"

type Blockchain struct {
	Blocks []*block.Block
}
