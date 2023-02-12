package transactions

import (
	"encoding/json"
	"fmt"
	"log"
)

type Transaction struct {
	TxType uint8               `json:"tx_type"`
	TxBody TransactionSpecific `json:"tx_body"`
	Data   []byte              `json:"data"`
	Nonce  uint32              `json:"nonce"`
}

func (tx *Transaction) GetStringToSign() string {
	return fmt.Sprintf("%d, %s, %v, %d", tx.TxType, tx.TxBody.GetStringToSign(), tx.Data, tx.Nonce)
}

func (tx *Transaction) String() string {
	str, _ := json.Marshal(tx)
	return string(str)
}

func (tx *Transaction) Print() {
	log.Println(tx)
}
