package object

import (
	"hash/fnv"
	"strings"
	"testing"
)

// Two strings whose FNV-1a-64 digests are equal. Finding a pair like this takes
// under a minute on an ordinary machine.
const (
	collidingA = "e38154aa4dee0878"
	collidingB = "c4272bece7a8573e"
)

func fnv64(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

// M26-EVL-003. A string's hash key was its FNV-1a-64 digest and nothing else,
// and every hash lookup in both engines went by the key alone. Two different
// strings with one digest were one entry: the second write replaced the first,
// and a lookup of either returned the other's value. Buffers were keyed the
// same way. A key now carries enough to be equal only to itself.
func TestTwoKeysWithOneDigestAreTwoKeys(t *testing.T) {
	if fnv64(collidingA) != fnv64(collidingB) {
		t.Fatal("the fixture no longer collides under FNV-1a-64")
	}

	a, b := (&String{Value: collidingA}).HashKey(), (&String{Value: collidingB}).HashKey()
	if a == b {
		t.Errorf("%q and %q are one hash key", collidingA, collidingB)
	}
	if a != (&String{Value: collidingA}).HashKey() {
		t.Error("one string gives two different hash keys")
	}

	bufA := (&Bytes{Value: []byte(collidingA)}).HashKey()
	bufB := (&Bytes{Value: []byte(collidingB)}).HashKey()
	if bufA == bufB {
		t.Errorf("buffers holding %q and %q are one hash key", collidingA, collidingB)
	}
	if bufA != (&Bytes{Value: []byte(collidingA)}).HashKey() {
		t.Error("one buffer gives two different hash keys")
	}
	// A buffer may be classified plaintext, and a map key is an immutable string
	// nothing can zero: the key holds a digest of the buffer, never the buffer.
	if strings.Contains(bufA.Text, collidingA) {
		t.Error("a buffer's hash key holds the buffer's own bytes")
	}
	if (&String{Value: collidingA}).HashKey() == bufA {
		t.Error("a string and a buffer with the same bytes are one hash key")
	}
}
