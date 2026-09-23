package evaluator

import (
	"testing"

	"mutant/object"
)

// The tree-walking engine joins buffers the way the VM does, mark included:
// classified plaintext joined to anything is still classified plaintext.
func TestConcatenatingClassifiedPlaintextKeepsTheMark(t *testing.T) {
	mark := &object.Classification{RecordUID: "rec", Tags: []string{"t"}, Labels: []string{"pii"}}
	for name, operands := range map[string][2]*object.Bytes{
		"on the left":  {{Value: []byte("secret"), Classified: mark}, {Value: []byte("-tail")}},
		"on the right": {{Value: []byte("head-")}, {Value: []byte("secret"), Classified: mark}},
	} {
		joined, ok := evalBytesInfixExpression("+", operands[0], operands[1]).(*object.Bytes)
		if !ok {
			t.Fatalf("%s: + did not produce a buffer", name)
		}
		if joined.Classified != mark {
			t.Fatalf("classified plaintext %s of a + lost its mark", name)
		}
	}
	plain := evalBytesInfixExpression("+", &object.Bytes{Value: []byte("a")}, &object.Bytes{Value: []byte("b")})
	if plain.(*object.Bytes).Classified != nil {
		t.Fatal("two unmarked buffers joined into a marked one")
	}
}
