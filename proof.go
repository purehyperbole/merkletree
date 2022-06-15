package merkletree

// Proof a merkle proof
type Proof []Pair

// Row represents a row used in a merkle tree proof
type Pair struct {
	Left  []byte
	Right []byte
}
