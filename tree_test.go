package merkletree

import (
	"crypto/sha256"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMerkleTreeBalanced(t *testing.T) {
	mt := New(100, func() hash.Hash {
		return sha256.New()
	})

	require.NotNil(t, mt.Insert([]byte("1")))
	require.NotNil(t, mt.Insert([]byte("2")))
	require.NotNil(t, mt.Insert([]byte("3")))
	require.NotNil(t, mt.Insert([]byte("4")))
	require.NotNil(t, mt.Insert([]byte("5")))
	require.NotNil(t, mt.Insert([]byte("6")))
	require.NotNil(t, mt.Insert([]byte("7")))
	require.NotNil(t, mt.Insert([]byte("8")))

	mrh := mt.Root()
	require.NotNil(t, mrh)

	hs := sha256.New()

	hs.Write(mt.nodes[0].hash)
	hs.Write(mt.nodes[1].hash)
	h1 := hs.Sum(nil)

	assert.Equal(t, mt.nodes[8].hash, h1)

	hs.Reset()

	hs.Write(mt.nodes[2].hash)
	hs.Write(mt.nodes[3].hash)
	h2 := hs.Sum(nil)

	assert.Equal(t, mt.nodes[9].hash, h2)

	hs.Reset()

	hs.Write(mt.nodes[4].hash)
	hs.Write(mt.nodes[5].hash)
	h3 := hs.Sum(nil)

	assert.Equal(t, mt.nodes[10].hash, h3)

	hs.Reset()

	hs.Write(mt.nodes[6].hash)
	hs.Write(mt.nodes[7].hash)
	h4 := hs.Sum(nil)

	assert.Equal(t, mt.nodes[11].hash, h4)

	hs.Reset()

	hs.Write(mt.nodes[8].hash)
	hs.Write(mt.nodes[9].hash)
	h5 := hs.Sum(nil)

	assert.Equal(t, mt.nodes[12].hash, h5)

	hs.Reset()

	hs.Write(mt.nodes[10].hash)
	hs.Write(mt.nodes[11].hash)
	h6 := hs.Sum(nil)

	assert.Equal(t, mt.nodes[13].hash, h6)

	hs.Reset()

	hs.Write(mt.nodes[12].hash)
	hs.Write(mt.nodes[13].hash)
	h7 := hs.Sum(nil)

	assert.Equal(t, mt.root, h7)
}

func TestMerkleTreeUnbalanced(t *testing.T) {
	mt := New(100, func() hash.Hash {
		return sha256.New()
	})

	require.NotNil(t, mt.Insert([]byte("1")))
	require.NotNil(t, mt.Insert([]byte("2")))
	require.NotNil(t, mt.Insert([]byte("3")))
	require.NotNil(t, mt.Insert([]byte("4")))
	require.NotNil(t, mt.Insert([]byte("5")))

	mrh := mt.Root()
	require.NotNil(t, mrh)

	hs := sha256.New()

	hs.Write(mt.nodes[0].hash)
	hs.Write(mt.nodes[1].hash)
	h1 := hs.Sum(nil)

	assert.Equal(t, mt.nodes[5].hash, h1)

	hs.Reset()

	hs.Write(mt.nodes[2].hash)
	hs.Write(mt.nodes[3].hash)
	h2 := hs.Sum(nil)

	assert.Equal(t, mt.nodes[6].hash, h2)

	hs.Reset()

	hs.Write(mt.nodes[4].hash)
	hs.Write(mt.nodes[4].hash)
	h3 := hs.Sum(nil)

	assert.Equal(t, mt.nodes[7].hash, h3)

	hs.Reset()

	hs.Write(mt.nodes[5].hash)
	hs.Write(mt.nodes[6].hash)
	h5 := hs.Sum(nil)

	assert.Equal(t, mt.nodes[8].hash, h5)

	hs.Reset()

	hs.Write(mt.nodes[7].hash)
	hs.Write(mt.nodes[7].hash)
	h6 := hs.Sum(nil)

	assert.Equal(t, mt.nodes[9].hash, h6)

	hs.Reset()

	hs.Write(mt.nodes[8].hash)
	hs.Write(mt.nodes[9].hash)
	h7 := hs.Sum(nil)

	assert.Equal(t, mrh, h7)
}
