package block

import (
	"fmt"
	"math/big"
	"strings"
)

type Header struct {
	Version    uint32   `json:"version"`
	Previous   *big.Int `json:"previous"`
	TimeStamp  uint64   `json:"time_stamp"`
	MerkleRoot *big.Int `json:"merkle_root"`
}

func (h Header) GetConcatenation() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprint(h.Version))
	sb.WriteString(h.Previous.String())
	sb.WriteString(fmt.Sprint(h.TimeStamp))
	sb.WriteString(h.MerkleRoot.String())

	return sb.String()
}
