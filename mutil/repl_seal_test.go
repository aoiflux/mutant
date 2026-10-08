package mutil

import (
	"bytes"
	"errors"
	"testing"

	"mutant/compiler"
	"mutant/object"
	"mutant/security"
)

func fnConstant(instructions ...byte) *object.CompiledFunction {
	return &object.CompiledFunction{Instructions: append([]byte{}, instructions...)}
}

// The property the REPL depends on: whatever seed a line's VM will derive from
// len(bc.Instructions), every compiled function in the pool is readable under
// it -- including the ones sealed two or three lines ago.
func TestReplSealerReKeysCarriedFunctionsToTheCurrentSeed(t *testing.T) {
	const password = "seal-test"
	body := []byte{9, 8, 7, 6, 5}

	sealer := NewReplSealer(password)
	fn := fnConstant(body...)

	// Line one: a nine-byte program that puts the function in the pool.
	first := &compiler.ByteCode{
		Instructions: bytes.Repeat([]byte{1}, 9),
		Constants:    []object.Object{fn},
	}
	if _, err := sealer.Seal(first); err != nil {
		t.Fatalf("line 1: %v", err)
	}
	wantFirst, err := security.SecureXOR(body, 9, password)
	if err != nil {
		t.Fatalf("reference ciphertext: %v", err)
	}
	if !bytes.Equal(fn.Instructions, wantFirst) {
		t.Fatalf("line 1 sealed the function under the wrong seed")
	}

	// Line two: a different length, so a different key. The same function
	// object has to come out readable under 13.
	second := &compiler.ByteCode{
		Instructions: bytes.Repeat([]byte{2}, 13),
		Constants:    []object.Object{fn},
	}
	if _, err := sealer.Seal(second); err != nil {
		t.Fatalf("line 2: %v", err)
	}
	wantSecond, err := security.SecureXOR(body, 13, password)
	if err != nil {
		t.Fatalf("reference ciphertext: %v", err)
	}
	if !bytes.Equal(fn.Instructions, wantSecond) {
		t.Fatalf("line 2 did not re-key the carried function to this line's seed")
	}

	// And the function object is the same one, which is what makes a closure
	// held in a global agree with the pool.
	if fn != second.Constants[0] {
		t.Fatal("the sealer replaced the function object instead of re-keying it in place")
	}

	// Line three adds a second function. The old one re-keys, the new one is
	// sealed for the first time, and both end up under 21.
	fresh := fnConstant(4, 3, 2)
	third := &compiler.ByteCode{
		Instructions: bytes.Repeat([]byte{3}, 21),
		Constants:    []object.Object{fn, fresh},
	}
	if _, err := sealer.Seal(third); err != nil {
		t.Fatalf("line 3: %v", err)
	}
	wantCarried, err := security.SecureXOR(body, 21, password)
	if err != nil {
		t.Fatalf("reference ciphertext: %v", err)
	}
	if !bytes.Equal(fn.Instructions, wantCarried) {
		t.Fatal("line 3 did not re-key the function carried from line 1")
	}
	wantFresh, err := security.SecureXOR([]byte{4, 3, 2}, 21, password)
	if err != nil {
		t.Fatalf("reference ciphertext: %v", err)
	}
	if !bytes.Equal(fresh.Instructions, wantFresh) {
		t.Fatal("line 3 did not seal the function it added")
	}
}

// A line whose instruction length happens to match the previous one needs no
// re-keying, and must not get one: XOR under the same key twice would hand the
// VM plaintext where it expects ciphertext.
func TestReplSealerLeavesAnUnchangedSeedAlone(t *testing.T) {
	const password = "same-seed"
	body := []byte{7, 7, 7}
	fn := fnConstant(body...)
	sealer := NewReplSealer(password)

	for line := 1; line <= 3; line++ {
		bc := &compiler.ByteCode{
			Instructions: bytes.Repeat([]byte{byte(line)}, 11),
			Constants:    []object.Object{fn},
		}
		if _, err := sealer.Seal(bc); err != nil {
			t.Fatalf("line %d: %v", line, err)
		}
	}

	want, err := security.SecureXOR(body, 11, password)
	if err != nil {
		t.Fatalf("reference ciphertext: %v", err)
	}
	if !bytes.Equal(fn.Instructions, want) {
		t.Fatal("three lines of the same length left the function unreadable")
	}
}

// Scalar constants keep the behaviour they already had: EncryptObject records
// its seed on the *object.Encrypted it returns, and a second pass over an
// already-wrapped value changes nothing.
func TestReplSealerDoesNotRewrapScalarConstants(t *testing.T) {
	sealer := NewReplSealer("scalars")
	original := &object.Integer{Value: 41}

	first := &compiler.ByteCode{
		Instructions: bytes.Repeat([]byte{1}, 6),
		Constants:    []object.Object{original},
	}
	sealedFirst, err := sealer.Seal(first)
	if err != nil {
		t.Fatalf("line 1: %v", err)
	}
	wrapped, ok := sealedFirst.Constants[0].(*object.Encrypted)
	if !ok {
		t.Fatalf("constant 0 is %T, want *object.Encrypted", sealedFirst.Constants[0])
	}
	if wrapped.Seed != 6 {
		t.Fatalf("recorded seed = %d, want 6", wrapped.Seed)
	}
	payload := append([]byte{}, wrapped.Value...)

	second := &compiler.ByteCode{
		Instructions: bytes.Repeat([]byte{2}, 18),
		Constants:    []object.Object{wrapped},
	}
	if _, err := sealer.Seal(second); err != nil {
		t.Fatalf("line 2: %v", err)
	}
	if wrapped.Seed != 6 || !bytes.Equal(wrapped.Value, payload) {
		t.Fatal("the second line re-encrypted a constant that already records its own seed")
	}

	back, err := DecryptObject(wrapped, 18, "scalars")
	if err != nil {
		t.Fatalf("decrypt under line 2's length: %v", err)
	}
	integer, ok := back.(*object.Integer)
	if !ok || integer.Value != 41 {
		t.Fatalf("read back %#v, want 41", back)
	}
}

// The refusals. A sealer that cannot re-key correctly writes nothing and says
// so, because a half-re-keyed pool cannot be recovered: the functions are
// shared with globals and nothing records which key each one currently holds.
func TestReplSealerRefusals(t *testing.T) {
	t.Run("empty password", func(t *testing.T) {
		sealer := NewReplSealer("")
		_, err := sealer.Seal(&compiler.ByteCode{Instructions: []byte{1, 2}})
		if !errors.Is(err, ErrReplSealerNoPassword) {
			t.Fatalf("err = %v, want ErrReplSealerNoPassword", err)
		}
	})

	t.Run("nil bytecode", func(t *testing.T) {
		sealer := NewReplSealer("pw")
		if _, err := sealer.Seal(nil); err == nil {
			t.Fatal("sealed a nil bytecode")
		}
	})

	t.Run("pool shrank", func(t *testing.T) {
		sealer := NewReplSealer("pw")
		first := &compiler.ByteCode{
			Instructions: bytes.Repeat([]byte{1}, 5),
			Constants:    []object.Object{fnConstant(1, 2, 3), fnConstant(4, 5, 6)},
		}
		if _, err := sealer.Seal(first); err != nil {
			t.Fatalf("line 1: %v", err)
		}

		shrunk := &compiler.ByteCode{
			Instructions: bytes.Repeat([]byte{2}, 7),
			Constants:    []object.Object{fnConstant(1, 2, 3)},
		}
		before := append([]byte{}, shrunk.Instructions...)
		_, err := sealer.Seal(shrunk)
		if !errors.Is(err, ErrReplSealerPoolShrank) {
			t.Fatalf("err = %v, want ErrReplSealerPoolShrank", err)
		}
		if !bytes.Equal(shrunk.Instructions, before) {
			t.Fatal("the refused line's instructions were encrypted anyway")
		}
	})
}

// A nil slot in the pool is skipped rather than panicked on. Nothing in the
// tree puts one there -- the compiler only appends -- but EncryptByteCode
// reaches Constants[i].Type() on it, and a sealer that runs once per line for
// a whole session should not inherit that.
func TestReplSealerSkipsANilConstant(t *testing.T) {
	sealer := NewReplSealer("nils")
	bc := &compiler.ByteCode{
		Instructions: bytes.Repeat([]byte{1}, 4),
		Constants:    []object.Object{nil, fnConstant(5, 6), nil},
	}
	sealed, err := sealer.Seal(bc)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if sealed.Constants[0] != nil || sealed.Constants[2] != nil {
		t.Fatal("a nil slot was replaced")
	}
	want, err := security.SecureXOR([]byte{5, 6}, 4, "nils")
	if err != nil {
		t.Fatalf("reference ciphertext: %v", err)
	}
	fn := sealed.Constants[1].(*object.CompiledFunction)
	if !bytes.Equal(fn.Instructions, want) {
		t.Fatal("the function beside the nil slots was not sealed")
	}

	// And a second line still re-keys it past the nil slots.
	next := &compiler.ByteCode{
		Instructions: bytes.Repeat([]byte{2}, 9),
		Constants:    []object.Object{nil, fn, nil},
	}
	if _, err := sealer.Seal(next); err != nil {
		t.Fatalf("line 2: %v", err)
	}
	want, err = security.SecureXOR([]byte{5, 6}, 9, "nils")
	if err != nil {
		t.Fatalf("reference ciphertext: %v", err)
	}
	if !bytes.Equal(fn.Instructions, want) {
		t.Fatal("the function was not re-keyed past the nil slots")
	}
}
