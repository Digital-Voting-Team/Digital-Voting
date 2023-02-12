package block

import (
	"fmt"
	"strings"
)

type Header struct {
	Version    uint32   `json:"version"`
	Previous   [32]byte `json:"previous"`
	TimeStamp  uint64   `json:"time_stamp"`
	MerkleRoot [32]byte `json:"merkle_root"`
}

func (h Header) GetConcatenation() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprint(h.Version))
	sb.Write(h.Previous[:])
	sb.WriteString(fmt.Sprint(h.TimeStamp))
	sb.Write(h.MerkleRoot[:])

	return sb.String()
}
