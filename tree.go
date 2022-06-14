package merkletree

import (
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

	t.nodes = append(t.nodes, &node{
		hash: h,
	})

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

	// if we have an odd number of nodes,
	// duplicate the last hash
	if len(t.nodes)%2 == 1 {
		t.nodes = append(t.nodes, t.nodes[len(t.nodes)-1].clone())
	}

	hs := t.hashpool.Get().(hash.Hash)

	start := 0
	end := t.leaves

	for end-start >= 2 {
		for i := start; i < end; i = i + 2 {
			fmt.Println(len(t.nodes), i, start, end)
			hs.Reset()
			hs.Write(t.nodes[i].hash)
			hs.Write(t.nodes[i+1].hash)
			h := hs.Sum(nil)

			n := &node{
				hash: h,
			}

			t.nodes[i].parent = n
			t.nodes[i+1].parent = n

			t.nodes = append(t.nodes, n)
		}

		start = end
		end = start + (start / 2)
	}

	// calculate the root hash and append it
	hs.Reset()
	hs.Write(t.nodes[len(t.nodes)-2].hash)
	hs.Write(t.nodes[len(t.nodes)-1].hash)
	h := hs.Sum(nil)

	n := &node{
		hash: h,
	}

	t.nodes[len(t.nodes)-2].parent = n
	t.nodes[len(t.nodes)-1].parent = n

	t.nodes = append(t.nodes, n)

	t.hashpool.Put(hs)

	t.root = h

	return t.root
}

// Proof generates a proof for a given hash included in the merkle tree
func (t *Tree) Proof(targetHash []byte) error {
	if t.root != nil {
		return errors.New("proof cannot be generated as the merkle root has not been constructed")
	}

	return nil
}
