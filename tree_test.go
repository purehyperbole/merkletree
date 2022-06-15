package merkletree

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"math/rand"
	"strconv"
	"testing"
	"time"

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

func TestMerkleTreeProofBalanced(t *testing.T) {
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

	proof, err := mt.Proof(mt.nodes[0].hash)
	require.Nil(t, err)
	require.Len(t, proof, 3)

	assert.Equal(t, testshash("2"), proof[0].Right)
	assert.Equal(t, testscombine("3", "4"), proof[1].Right)
	assert.Equal(t, mt.nodes[13].hash, proof[2].Right)
}

func TestMerkleTreeProofUnbalanced(t *testing.T) {
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

	proof, err := mt.Proof(mt.nodes[4].hash)
	require.Nil(t, err)
	require.Len(t, proof, 3)

	assert.Equal(t, testshash("5"), proof[0].Right)
	assert.Equal(t, testscombine("5", "5"), proof[1].Right)
	assert.Equal(t, mt.nodes[8].hash, proof[2].Left)
}

func TestMerkleTreeValidate(t *testing.T) {
	mt := New(1000, func() hash.Hash {
		return sha256.New()
	})

	vh := make([][]byte, 0, 1000)

	for i := 0; i < 1000; i++ {
		vh = append(vh, mt.Insert([]byte(strconv.Itoa(i))))
	}

	mrh := mt.Root()

	// test some random entries for proofs
	for i := 0; i < 50; i++ {
		target := vh[rand.Intn(1000)]

		proof, err := mt.Proof(target)
		require.Nil(t, err)
		assert.NotNil(t, proof)

		err = Validate(sha256.New(), target, mrh, proof)
		require.Nil(t, err)
	}

	// test an invalid target hash
	proof, err := mt.Proof(testshash("invalid"))
	require.NotNil(t, err)
	require.Nil(t, proof)

	proof, err = mt.Proof(vh[0])
	require.Nil(t, err)

	err = Validate(sha256.New(), testshash("invalid"), mrh, proof)
	require.NotNil(t, err)

	// test an invalid root hash
	err = Validate(sha256.New(), vh[0], testshash("invalid"), proof)
	require.NotNil(t, err)
}

func TestMerkleTreeLarge(t *testing.T) {
	mt := New(100000, func() hash.Hash {
		return sha256.New()
	})

	start := time.Now()
	for i := 0; i < 100000; i++ {
		mt.Insert([]byte(strconv.Itoa(i)))
	}

	fmt.Println("insert took: ", time.Since(start))

	start = time.Now()
	mt.Root()

	fmt.Println("root took: ", time.Since(start))
}

func testshash(a string) []byte {
	return testhash([]byte(a))
}

func testhash(a []byte) []byte {
	h := sha256.New()

	h.Write(a)
	return h.Sum(nil)
}

func testscombine(a, b string) []byte {
	return testcombine([]byte(a), []byte(b))
}

func testcombine(a, b []byte) []byte {
	h := sha256.New()

	h.Write(a)
	ah := h.Sum(nil)

	h.Reset()
	h.Write(b)

	bh := h.Sum(nil)

	h.Reset()
	h.Write(ah)
	h.Write(bh)

	return h.Sum(nil)
}
