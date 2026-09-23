package vm

import (
	"strings"
	"testing"

	"mutant/compiler"
	"mutant/object"
)

// markConstants compiles src and swaps each string constant named in marks
// for a classified buffer, which is how plaintext read out of a record would
// arrive -- a program cannot make one without a case key, and a test of the
// VM should not need one.
func markConstants(t *testing.T, src string, marks map[string]*object.Bytes) *compiler.ByteCode {
	t.Helper()
	bc := compileFresh(t, src)
	swapped := 0
	for i, constant := range bc.Constants {
		if s, ok := constant.(*object.String); ok {
			if buffer, named := marks[s.Value]; named {
				bc.Constants[i] = buffer
				swapped++
			}
		}
	}
	if swapped != len(marks) {
		t.Fatalf("swapped %d of %d placeholders; the program did not compile to the constants this test expects",
			swapped, len(marks))
	}
	return bc
}

// The sink checks in builtin/classified.go are only as good as this. Every
// variable the VM holds is stored encrypted at rest, and until the mark rode
// beside the ciphertext a buffer lost it the moment it was bound to a name --
// so every sink in a real program was handed an unmarked buffer and passed it.
func TestAClassifiedBufferKeepsItsMarkInTheVM(t *testing.T) {
	left := &object.Classification{RecordUID: "rec-a", Tags: []string{"t-pii"}, Labels: []string{"pii"}}
	right := &object.Classification{RecordUID: "rec-b", Tags: []string{"t-restricted"}, Labels: []string{"restricted"}}
	marks := func() map[string]*object.Bytes {
		return map[string]*object.Bytes{
			"LEFT":  {Value: []byte("secret"), Classified: left},
			"RIGHT": {Value: []byte("-tail"), Classified: right},
		}
	}

	t.Run("held in a global, a local and a captured variable", func(t *testing.T) {
		src := `let a = "LEFT";
let b = "RIGHT";
let hold = fn(x) {
	let held = x;
	let give = fn() { return held; };
	return give();
};
hold(a);`
		machine, err := runSealed(t, markConstants(t, src, marks()))
		if err != nil {
			t.Fatal(err)
		}
		got, ok := machine.LastPoppedStackElement().(*object.Bytes)
		if !ok || string(got.Value) != "secret" {
			t.Fatalf("the program returned %#v", machine.LastPoppedStackElement())
		}
		if got.Classified != left {
			t.Fatal("a classified buffer lost its mark by being held in a variable")
		}
	})

	t.Run("concatenated", func(t *testing.T) {
		src := `let a = "LEFT";
let b = "RIGHT";
let plain = a + b;
plain;`
		machine, err := runSealed(t, markConstants(t, src, marks()))
		if err != nil {
			t.Fatal(err)
		}
		got, ok := machine.LastPoppedStackElement().(*object.Bytes)
		if !ok || string(got.Value) != "secret-tail" {
			t.Fatalf("the program returned %#v", machine.LastPoppedStackElement())
		}
		if got.Classified == nil {
			t.Fatal("concatenating classified plaintext produced an unmarked buffer")
		}
		if !strings.Contains(got.Classified.RecordUID, "rec-a") || !strings.Contains(got.Classified.RecordUID, "rec-b") ||
			strings.Join(got.Classified.Labels, ",") != "pii,restricted" {
			t.Fatalf("the joined buffer is marked %+v, not with both records and both classes", got.Classified)
		}
	})
}
