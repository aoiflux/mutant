package evaluator

import (
	"testing"

	"mutant/object"
)

// The error is produced by a failing builtin rather than constructed, because
// nothing in the language constructs one yet.
const evalRaisingProgram = `let d, err = fs_read("/mutant/evaluator/no/such/path"); `

// The evaluator has one Error type doing two jobs -- the language's error value
// and the tree-walker's fatal signal -- and before evalInspectedOperand the
// short-circuit for the second swallowed the first: err.message evaluated to the
// error itself, silently. These are the tests for that seam, so they check the
// value read *and* the fault that must still propagate.
func TestErrorFieldsReadOffABoundError(t *testing.T) {
	cases := []struct {
		expr string
		want string
	}{
		{"err.context", "builtin.fs_read"},
		{`err["context"]`, "builtin.fs_read"},
	}

	for _, tc := range cases {
		result := testEval(evalRaisingProgram + tc.expr)
		got, ok := result.(*object.String)
		if !ok {
			t.Fatalf("%s yielded %s (%s), want a string",
				tc.expr, result.Type(), result.Inspect())
		}
		if got.Value != tc.want {
			t.Errorf("%s = %q, want %q", tc.expr, got.Value, tc.want)
		}
	}

	if got := testEval(evalRaisingProgram + "type_of(err.related)"); got.Inspect() != "HASH" {
		t.Errorf("err.related is %s, want a hash", got.Inspect())
	}
	if got := testEval(evalRaisingProgram + "type_of(err.stack)"); got.Inspect() != "ARRAY" {
		t.Errorf("err.stack is %s, want an array", got.Inspect())
	}
	if got := testEval(evalRaisingProgram + "err.no_such_field"); got.Type() != object.NULL_OBJ {
		t.Errorf("an unknown field is %s, want NULL", got.Type())
	}
}

// The other half of the seam. Reading a field off an unbound name is still a
// fault and must still propagate -- if it did not, a typo would evaluate to
// whatever field name followed it instead of being reported.
func TestAFaultOnTheLeftOfAFieldAccessStillPropagates(t *testing.T) {
	result := testEval("no_such_binding.message")

	errObj, ok := result.(*object.Error)
	if !ok {
		t.Fatalf("reading a field off an unbound name yielded %s, want an error", result.Type())
	}
	if errObj.Message != "identifier not found: no_such_binding" {
		t.Errorf("fault reported as %q", errObj.Message)
	}
}

// Indexing takes the same seam, so it gets the same pair of checks.
func TestAFaultOnTheLeftOfAnIndexStillPropagates(t *testing.T) {
	result := testEval(`no_such_binding["message"]`)

	if _, ok := result.(*object.Error); !ok {
		t.Fatalf("indexing an unbound name yielded %s, want an error", result.Type())
	}
}

// The evaluator never stamps a position -- only the VM does -- but the shape is
// the same either way, which is the guarantee that lets a program read err.line
// without knowing which engine it is on.
func TestEvaluatorErrorPositionFieldsAreIntegers(t *testing.T) {
	for _, expr := range []string{"err.line", "err.column", "err.end_line", "err.end_column"} {
		got, ok := testEval(evalRaisingProgram + expr).(*object.Integer)
		if !ok {
			t.Fatalf("%s is not an integer", expr)
		}
		if got.Value != 0 {
			t.Errorf("%s = %d, want 0 -- the evaluator stamps no position", expr, got.Value)
		}
	}
}
