package transactions

type Address string
type Signature string

type votingCreationTx struct {
	transactionType   uint8
	expirationDate    uint32
	votingDescription [1024]byte
	answers           [4][256]byte
	whitelist         [256]Address
	adminPbk          Address
	signature         Signature
	nonce             uint32
}
