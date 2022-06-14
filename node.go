package merkletree

type node struct {
	parent    *node
	leaf      bool
	duplicate bool
	hash      []byte
}

func (n *node) clone() *node {
	return &node{
		parent:    n.parent,
		leaf:      n.leaf,
		duplicate: true,
		hash:      n.hash,
	}
}
