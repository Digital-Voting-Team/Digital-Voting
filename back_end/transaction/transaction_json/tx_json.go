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

func (tx *JSONTransaction) UnmarshallJSON(data []byte) (transaction.ITransaction, error) {
	temp := make(map[string]interface{})
	err := json.Unmarshal(data, &temp)
	if err != nil {
		return nil, err
	}

	tx.TxType = transaction.TxType(uint8(temp["tx_type"].(float64)))

	val, ok := temp["private_key"]
	if ok {
		marshal, _ := json.Marshal(val)
		err = json.Unmarshal(marshal, &tx.PrivateKey)
		if err != nil {
			return nil, err
		}
	}

	val, ok = temp["nonce"]
	if ok {
		tx.Nonce = uint32(val.(float64))
	}

	val, ok = temp["data"]
	if ok {
		marshal, _ := json.Marshal(val)
		err = json.Unmarshal(marshal, &tx.Data)
		if err != nil {
			return nil, err
		}
	}

	var txBody transaction.TxBody

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
		var returnTransaction *transaction_specific.TxVoteAnonymous

		marshal, _ := json.Marshal(temp["voting_link"])
		err = json.Unmarshal(marshal, &tx.VotingLink)
		if err != nil {
			return nil, err
		}
		tx.Answer = uint8(temp["answer"].(float64))

		// Check whether it is new transaction or just for verification
		if tx.Nonce == 0 {
			tx.RingSize = uint8(temp["ring_size"].(float64))

			returnTransaction = transaction_specific.NewTxVoteAnonymous(tx.VotingLink, tx.Answer)
		} else {
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

	marshal, _ := json.Marshal(temp["tx_body"])

	err = json.Unmarshal(marshal, txBody)
	if err != nil {
		return nil, err
	}
	tx.TxBody = txBody

	var returnTransaction *transaction.Transaction

	// Check whether it is new transaction or just for verification
	if tx.Nonce == 0 {
		returnTransaction = transaction.NewTransaction(tx.TxType, tx.TxBody)
	} else {
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
