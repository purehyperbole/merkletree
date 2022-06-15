package merkletree

type node struct {
	index  int
	parent *node
	left   *node
	right  *node
	leaf   bool
	hash   []byte
}
