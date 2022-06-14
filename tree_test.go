package merkletree

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMerkleTreeOdd(t *testing.T) {
	mt := New(100, func() hash.Hash {
		return sha256.New()
	})

	require.NotNil(t, mt.Insert([]byte("1")))

	fmt.Println(mt)

	require.NotNil(t, mt.Root())

	fmt.Println(mt)
}

func TestMerkleTreeEven(t *testing.T) {
	mt := New(100, func() hash.Hash {
		return sha256.New()
	})

	require.NotNil(t, mt.Insert([]byte("1")))
	require.NotNil(t, mt.Insert([]byte("2")))

	fmt.Println(mt)

	require.NotNil(t, mt.Root())

	fmt.Println(mt)
}

func TestMerkleTreeMultiple(t *testing.T) {
	mt := New(100, func() hash.Hash {
		return sha256.New()
	})

	require.NotNil(t, mt.Insert([]byte("1")))
	require.NotNil(t, mt.Insert([]byte("2")))
	require.NotNil(t, mt.Insert([]byte("3")))
	require.NotNil(t, mt.Insert([]byte("4")))
	require.NotNil(t, mt.Insert([]byte("5")))
	require.NotNil(t, mt.Insert([]byte("6")))

	fmt.Println(mt)

	require.NotNil(t, mt.Root())

	fmt.Println(mt)
}
