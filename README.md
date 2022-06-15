# merkletree
A thread safe merkle tree for golang

# Usage

```go
package main

import (
    "crypto/sha256"
    "fmt"

    "github.com/purehyperbole/merkletree"
)

func main() {
    m := merkletree.New(1024, func() hash.Hash {
        return sha256.New()
    })

    // insert the hashes of some values into the tree
    // the hash of the value will be returned
    h1 := m.Insert([]byte("my data 1"))
    h2 := m.Insert([]byte("my data 2"))
    h3 := m.Insert([]byte("my data 3"))

    // generate the merkle root hash. Note, this can only be called once
    mrh := m.Root()

    // generate a proof for 'my data 2' from the generated merkle tree
    proof, err := m.Proof(h2)
    if err != nil {
        panic(err)
    }

    // validate the proof against the hash of the value and merkle root
    err = merkletree.Validate(sha256.New(), h2, mrh, proof)
    if err != nil {
        panic(err)
    }
}

```