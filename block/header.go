package block

import "github.com/holiman/uint256"

type header struct {
	version           uint32
	previous          uint256.Int
	timeStamp         uint32
	merkleRoot        uint256.Int
	witnessMerkleRoot uint256.Int
}
