package block

type transaction interface {
}

type Body struct {
	Transactions []transaction `json:"transactions"`
}

func (b *Body) AddTransaction(myTransaction transaction) {
	b.Transactions = append(b.Transactions, myTransaction)
}
