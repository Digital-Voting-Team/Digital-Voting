package block

type transaction interface {
}

type body struct {
	transactions []transaction
}
