package validator

import (
	blk "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/block"
	tx "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository/indexed_votings"
)

type Communication struct {
	NetworkToValidator chan *blk.Block
	ValidatorToNetwork chan *blk.Block
	BlockResponse      chan ResponseMessage

	BlockApproval    chan *blk.Block
	ApprovalResponse chan bool

	BlockDenial chan *blk.Block

	Transaction chan tx.ITransaction
	TxResponse  chan bool

	ValidatorKeys chan []keys.PublicKeyBytes

	Votings   chan []indexed_votings.VotingDTO
	PublicKey chan keys.PublicKeyBytes
}
