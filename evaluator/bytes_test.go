package evaluator

import (
	"bytes"
	"testing"

	"mutant/object"
)

// evalBytes runs src and follows the (value, err) convention into its pair, so
// a test can name the value half without repeating the unwrap each time.
func evalBytes(t *testing.T, src string) object.Object {
	t.Helper()

	result := testEval(src)
	if errObj, isErr := result.(*object.Error); isErr {
		t.Fatalf("eval %q: %s", src, errObj.Message)
	}
	if multi, ok := result.(*object.MultiValue); ok && len(multi.Values) > 0 {
		return multi.Values[0]
	}
	return result
}

// The evaluator is a second engine, not a fallback: it runs the REPL and macro
// expansion. Everything the VM learned about buffers it had to learn too, and
// parity/ compares the two on the same corpus.
func TestEvaluatorHandlesBytes(t *testing.T) {
	t.Run("concatenation", func(t *testing.T) {
		src := `let a, e1 = string_to_bytes("4d5a", "hex");
let b, e2 = string_to_bytes("9000", "hex");
a + b`

		buf, ok := evalBytes(t, src).(*object.Bytes)
		if !ok {
			t.Fatalf("bytes + bytes produced %T", evalBytes(t, src))
		}
		if !bytes.Equal(buf.Value, []byte{0x4d, 0x5a, 0x90, 0x00}) {
			t.Errorf("concatenation = %x, want 4d5a9000", buf.Value)
		}
	})

	t.Run("indexing yields an integer", func(t *testing.T) {
		// The evaluator has never indexed strings while the VM has -- a
		// divergence that predates this type. Implementing bytes indexing in
		// both engines is what stops the new type from inheriting it.
		src := `let b, e = string_to_bytes("4d5a90", "hex");
b[2]`

		got, ok := evalBytes(t, src).(*object.Integer)
		if !ok {
			t.Fatalf("b[2] produced %T, want INTEGER", evalBytes(t, src))
		}
		if got.Value != 0x90 {
			t.Errorf("b[2] = %d, want %d", got.Value, 0x90)
		}
	})

	t.Run("equality is by content and type", func(t *testing.T) {
		cases := []struct {
			src  string
			want bool
		}{
			{`let a, e1 = string_to_bytes("4d5a", "hex");
let b, e2 = string_to_bytes("4d5a", "hex");
a == b`, true},
			{`let a, e1 = string_to_bytes("4d5a", "hex");
let b, e2 = string_to_bytes("9000", "hex");
a == b`, false},
			// The Inspect fallback would make this true without an explicit arm.
			{`let a, e1 = string_to_bytes("4d5a", "hex");
a == "4d5a"`, false},
			{`let a, e1 = string_to_bytes("4d5a", "hex");
a != "4d5a"`, true},
		}

		for _, tc := range cases {
			got, ok := evalBytes(t, tc.src).(*object.Boolean)
			if !ok {
				t.Fatalf("%q produced %T, want BOOLEAN", tc.src, evalBytes(t, tc.src))
			}
			if got.Value != tc.want {
				t.Errorf("%q = %v, want %v", tc.src, got.Value, tc.want)
			}
		}
	})

	t.Run("truthiness and length", func(t *testing.T) {
		if got := evalBytes(t, "let b, e = string_to_bytes(\"\", \"raw\");\nif (b) { 1 } else { 0 }"); got.Inspect() != "0" {
			t.Errorf("an empty buffer is truthy in the evaluator: %s", got.Inspect())
		}
		if got := evalBytes(t, "let b, e = string_to_bytes(\"4d5a\", \"hex\");\nlen(b)"); got.Inspect() != "2" {
			t.Errorf("len(buffer) = %s, want 2", got.Inspect())
		}
	})
}
