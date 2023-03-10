package transaction

// ITransaction TODO: think of moving interface into packages for their specific purposes (merkle_tree, block etc.)
type ITransaction interface {
	HashString() string
	Print()
}
