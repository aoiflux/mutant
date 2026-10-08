package security

import (
	"bytes"
	"testing"
)

// An XORStream is a derived key, and M26-VM-001 widened what it covers: it was
// the instruction stream, and it now seals the VM's values too. That makes its
// lifetime a question it was not before, because the runtime zeroes the
// password at teardown and a key derived from a secret must not outlive the
// secret.

func TestANewStreamIsTheKeyTheDerivationGives(t *testing.T) {
	const seed = 99
	const password = "a password"
	data := []byte("eight by.")

	stream := NewXORStream(seed, password)
	fromStream, err := stream.XORAt(data, 0)
	if err != nil {
		t.Fatalf("stream: %s", err)
	}
	derived, err := SecureXOR(data, seed, password)
	if err != nil {
		t.Fatalf("derive: %s", err)
	}

	// mutil hands a value's payload to one or the other depending on whether
	// the caller had a stream, so these two being the same is what makes a
	// stored value readable either way.
	if !bytes.Equal(fromStream, derived) {
		t.Errorf("the stream gave %x where deriving gives %x", fromStream, derived)
	}
}

func TestZeroWipesTheDerivedKey(t *testing.T) {
	stream := NewXORStream(99, "a password")
	data := []byte("eight by.")

	before, err := stream.XORAt(data, 0)
	if err != nil {
		t.Fatalf("before: %s", err)
	}

	stream.Zero()

	if stream.key != ([32]byte{}) {
		t.Error("the key survived Zero")
	}
	if stream.nonce != ([12]byte{}) {
		t.Error("the nonce survived Zero")
	}

	// Wiped, not dropped: the fetch loop reads the stream field directly, so a
	// use after teardown must not be a nil dereference. It is a wrong answer
	// instead, which is the same shape the wiped stack and globals beside it
	// take.
	after, err := stream.XORAt(data, 0)
	if err != nil {
		t.Fatalf("after: %s", err)
	}
	if bytes.Equal(before, after) {
		t.Error("the stream produced its original keystream after being wiped")
	}
}

func TestZeroOnNoStreamIsNotACrash(t *testing.T) {
	var stream *XORStream
	stream.Zero()
}
