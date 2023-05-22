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

	// TxType is available in all transactions
	tx.TxType = transaction.TxType(uint8(temp["tx_type"].(float64)))

	// PrivateKey is available for further signing if it is a new transaction
	// TODO: consider moving signing to the client for security reasons
	val, ok := temp["private_key"]
	if ok {
		marshal, _ := json.Marshal(val)
		err = json.Unmarshal(marshal, &tx.PrivateKey)
		if err != nil {
			return nil, err
		}
	}

	// Nonce is available only if it is already created and marshalled transaction
	val, ok = temp["nonce"]
	newTxFlag := !ok
	if ok {
		tx.Nonce = uint32(val.(float64))
	}

	// Data field is yet unused but can be filled with data
	val, ok = temp["data"]
	if ok {
		marshal, _ := json.Marshal(val)
		err = json.Unmarshal(marshal, &tx.Data)
		if err != nil {
			return nil, err
		}
	}

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

		// Voting link and answer are the fields necessary to construct VoteAnonymous transaction
		marshal, _ := json.Marshal(temp["voting_link"])
		err = json.Unmarshal(marshal, &tx.VotingLink)
		if err != nil {
			return nil, err
		}
		tx.Answer = uint8(temp["answer"].(float64))

		// Check whether it is new transaction or just for verification
		if newTxFlag {
			tx.RingSize = uint8(temp["ring_size"].(float64))

			returnTransaction = transaction_specific.NewTxVoteAnonymous(tx.VotingLink, tx.Answer)
		} else {
			// Read all necessary fields for already created and signed VoteAnonymous transaction
			marshal, _ = json.Marshal(temp["ring_signature"])
			err = json.Unmarshal(marshal, &tx.RingSignature)
			if err != nil {
				return nil, err
			}

			marshal, _ = json.Marshal(temp["key_image"])
			err = json.Unmarshal(marshal, &tx.KeyImage)
			if err != nil {
				return nil, err
			}

			marshal, _ = json.Marshal(temp["public_keys"])
			err = json.Unmarshal(marshal, &tx.PublicKeys)
			if err != nil {
				return nil, err
			}

			returnTransaction = &transaction_specific.TxVoteAnonymous{
				TxType:        tx.TxType,
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
		// Read all necessary fields for already created and signed Transaction
		marshal, _ = json.Marshal(temp["signature"])
		err = json.Unmarshal(marshal, &tx.Signature)
		if err != nil {
			return nil, err
		}

		marshal, _ = json.Marshal(temp["public_key"])
		err = json.Unmarshal(marshal, &tx.PublicKey)
		if err != nil {
			return nil, err
		}

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
