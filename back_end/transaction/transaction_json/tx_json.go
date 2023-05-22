package transaction_json

import (
	"digital-voting/signature/keys"
	rs "digital-voting/signature/signatures/ring_signature"
	ss "digital-voting/signature/signatures/single_signature"
	"digital-voting/transaction"
	"digital-voting/transaction/transaction_specific"
	"encoding/json"
	"fmt"
)

type JSONTransaction struct {
	TxType transaction.TxType `json:"tx_type"`

	TxBody     transaction.TxBody `json:"tx_body,omitempty"`
	VotingLink [32]byte           `json:"voting_link,omitempty"`
	Answer     uint8              `json:"answer,omitempty"`
	RingSize   uint8              `json:"ring_size,omitempty"`

	// TODO: consider not sending PrivateKey and moving signing to the client for security reasons
	PrivateKey keys.PrivateKeyBytes `json:"private_key,omitempty"`

	Data  []byte `json:"data,omitempty"`
	Nonce uint32 `json:"nonce,omitempty"`

	Signature ss.SingleSignatureBytes `json:"signature,omitempty"`
	PublicKey keys.PublicKeyBytes     `json:"public_key,omitempty"`

	RingSignature rs.RingSignatureBytes `json:"ring_signature,omitempty"`
	KeyImage      rs.KeyImageBytes      `json:"key_image,omitempty"`
	PublicKeys    []keys.PublicKeyBytes `json:"public_keys,omitempty"`
}

// UnmarshallJSON unmarshalls the JSON representation of the ITransaction into the ITransaction itself
// the function also unmarshalls other useful data like PrivateKey for signing and (or) RingSize for ring signature.
// This function unmarshalls in 2 cases:
// - when it is a new transaction ready to be signed
// - when it is already signed transaction
func (tx *JSONTransaction) UnmarshallJSON(marshalledTransaction []byte) (transaction.ITransaction, error) {
	temp := map[string]interface{}{}
	err := json.Unmarshal(marshalledTransaction, &temp)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(marshalledTransaction, tx)

	// Nonce is available only if it is already created and marshalled transaction
	newTxFlag := tx.Nonce == 0

	var txBody transaction.TxBody

	// TxBody can be different and is un=marshalled via switch
	switch tx.TxType {
	case transaction.AccountCreation:
		txBody = new(transaction_specific.TxAccountCreation)
	case transaction.GroupCreation:
		txBody = new(transaction_specific.TxGroupCreation)
	case transaction.VotingCreation:
		txBody = new(transaction_specific.TxVotingCreation)
	case transaction.Vote:
		txBody = new(transaction_specific.TxVote)
	case transaction.VoteAnonymous:
		// VoteAnonymous case is specific since this transaction is not usual and uses a different signature
		var returnTransaction *transaction_specific.TxVoteAnonymous
		// Check whether it is new transaction or just for verification
		if newTxFlag {
			returnTransaction = transaction_specific.NewTxVoteAnonymous(tx.VotingLink, tx.Answer)
		} else {
			returnTransaction = &transaction_specific.TxVoteAnonymous{
				TxType:        tx.TxType,
				VotingLink:    tx.VotingLink,
				Answer:        tx.Answer,
				Nonce:         tx.Nonce,
				RingSignature: tx.RingSignature,
				KeyImage:      tx.KeyImage,
				PublicKeys:    tx.PublicKeys,
			}
		}

		if len(tx.Data) != 0 {
			returnTransaction.Data = tx.Data
		}

		return returnTransaction, nil
	default:
		return nil, fmt.Errorf("unknown tx type: %d", tx.TxType)
	}

	// Marshall and unmarshall TxBody to set its fields
	marshal, _ := json.Marshal(temp["tx_body"])

	err = json.Unmarshal(marshal, txBody)
	if err != nil {
		return nil, err
	}
	tx.TxBody = txBody

	var returnTransaction *transaction.Transaction

	// Check whether it is new transaction or just for verification
	if newTxFlag {
		returnTransaction = transaction.NewTransaction(tx.TxType, tx.TxBody)
	} else {
		returnTransaction = &transaction.Transaction{
			TxType:    tx.TxType,
			TxBody:    tx.TxBody,
			Nonce:     tx.Nonce,
			Signature: tx.Signature,
			PublicKey: tx.PublicKey,
		}
	}

	if len(tx.Data) != 0 {
		returnTransaction.Data = tx.Data
	}

	return returnTransaction, nil
}
