package transaction

type ITransaction interface {
	HashString() string
	Print()
}
