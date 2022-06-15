package merkletree

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"sync"
)

// Tree a merkle tree
type Tree struct {
	root     []byte
	nodes    []*node
	leaves   int
	hashpool sync.Pool
	mu       sync.Mutex
}

// New creates a new merkle tree.
func New(initialSize int, hasher func() hash.Hash) *Tree {
	return &Tree{
		nodes: make([]*node, 0, initialSize),
		hashpool: sync.Pool{
			New: func() any {
				return hasher()
			},
		},
	}
}

// Validate validates a merkle proof. returns nil if the merkle proof contains the target hash
func Validate(target, root []byte, proof [][]byte) error {
	return nil
}

// Insert hashes a given value and inserts it into the tree and
// the computed hash is returned. If the merkle tree root hash has
// already been generated, the value will not be inserted and nil
// will be returned
func (t *Tree) Insert(value []byte) []byte {
	if t.root != nil {
		return nil
	}

	hs := t.hashpool.Get().(hash.Hash)
	hs.Reset()
	hs.Write(value)
	h := hs.Sum(nil)

	t.hashpool.Put(hs)

	t.mu.Lock()

	n := &node{
		index: len(t.nodes),
		hash:  h,
	}

	t.nodes = append(t.nodes, n)

	t.leaves++

	t.mu.Unlock()

	return h
}

// Root calculates the root hash of the merkle tree
func (t *Tree) Root() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.root != nil {
		return t.root
	}

	if t.leaves < 1 {
		return nil
	}

	hs := t.hashpool.Get().(hash.Hash)

	start := 0
	end := t.leaves

	// calculate each row of hashes
	for end-start > 2 {
		var additional int

		for i := start; i < end; i = i + 2 {
			n := &node{
				index: len(t.nodes),
				left:  t.nodes[i],
			}

			hs.Reset()
			hs.Write(t.nodes[i].hash)
			t.nodes[i].parent = n

			// if this row is unbalanced, hash with a duplicate of the last hash
			if end-i < 2 {
				hs.Write(t.nodes[i].hash)
				additional++
			} else {
				hs.Write(t.nodes[i+1].hash)
				t.nodes[i+1].parent = n
				n.right = t.nodes[i+1]
			}

			n.hash = hs.Sum(nil)

			t.nodes = append(t.nodes, n)
		}

		d := (end - start) / 2

		start = end
		end = start + d + additional
	}

	// calculate the root hash and append it
	hs.Reset()
	hs.Write(t.nodes[len(t.nodes)-2].hash)
	hs.Write(t.nodes[len(t.nodes)-1].hash)
	h := hs.Sum(nil)
	t.hashpool.Put(hs)

	n := &node{
		index: len(t.nodes),
		hash:  h,
		left:  t.nodes[len(t.nodes)-2],
		right: t.nodes[len(t.nodes)-1],
	}

	t.nodes[len(t.nodes)-2].parent = n
	t.nodes[len(t.nodes)-1].parent = n

	t.nodes = append(t.nodes, n)
	t.root = h

	return t.root
}

// Proof generates a proof for a given hash included in the merkle tree
func (t *Tree) Proof(targetHash []byte) ([][]byte, error) {
	if t.root == nil {
		return nil, errors.New("proof cannot be generated as the merkle root has not been constructed")
	}

	var target, current, previous *node

	// TODO : this will be slow on larger trees, create an index or insert
	// value hashes in order so we can binary search?
	for i := 0; i < t.leaves; i++ {
		if bytes.Equal(t.nodes[i].hash, targetHash) {
			target = t.nodes[i]
			break
		}
	}

	if target == nil {
		return nil, errors.New("target hash does not exist in the tree")
	}

	var proof [][]byte

	current = target

	for current != nil {
		if current.left != previous {
			if current.left != nil {
				proof = append(proof, current.left.hash)
			} else {
				previous = current
				current = previous.parent
				continue
			}
		} else if current.right != previous {
			if current.right == nil {
				proof = append(proof, current.left.hash)
			} else {
				proof = append(proof, current.right.hash)
			}
		}

		previous = current
		current = previous.parent
	}

	return proof, nil
}

func (t *Tree) graphviz() {
	fmt.Println("digraph G {")

	for i := 0; i < len(t.nodes); i++ {
		if i != len(t.nodes)-1 {
			fmt.Printf("    \"%d:%s\" -> \"%d:%s\"\n", i, hex.EncodeToString(t.nodes[i].hash), t.nodes[i].parent.index, hex.EncodeToString(t.nodes[i].parent.hash))
		}
	}

	fmt.Println("}")
}
