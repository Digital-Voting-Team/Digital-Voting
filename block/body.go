package block

type transaction any

type Body struct {
	Transactions []transaction `json:"transactions"`
}
