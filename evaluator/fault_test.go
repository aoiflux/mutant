package evaluator

import (
	"testing"

	"mutant/object"
)

// The evaluator distinguishes a fault -- "this expression cannot produce a
// value" -- from an error value a program is holding. Before error() existed
// nothing forced the two apart, because every error a program could hold
// arrived inside a MULTI_VALUE and the fault check never saw one.
//
// These tests pin both directions, because the failure modes are opposite and
// each looks like correct behaviour from the other side: treat a value as a
// fault and error() silently aborts the program, treat a fault as a value and a
// genuine mistake keeps running with an error bound to a name.

func TestAConstructedErrorIsAValue(t *testing.T) {
	result := testEval(`let e = error("boom"); e.message`)

	str, ok := result.(*object.String)
	if !ok {
		t.Fatalf("e.message gave %T (%+v), want a string -- the error was treated as a fault", result, result)
	}
	if str.Value != "boom" {
		t.Errorf("message = %q, want %q", str.Value, "boom")
	}
}

// A statement that merely evaluates to an error does not end the block. This is
// the case the old single ERROR_OBJ test got wrong once errors became values.
func TestAnErrorValueDoesNotEndABlock(t *testing.T) {
	result := testEval(`if (true) { error("ignored"); 5 }`)

	integer, ok := result.(*object.Integer)
	if !ok {
		t.Fatalf("block gave %T (%+v), want 5 -- an error value ended the block", result, result)
	}
	if integer.Value != 5 {
		t.Errorf("got %d, want 5", integer.Value)
	}
}

func TestAConstructedErrorSurvivesAFunctionReturn(t *testing.T) {
	result := testEval(`let f = fn() { return error("inner"); }; let e = f(); e.context`)

	str, ok := result.(*object.String)
	if !ok {
		t.Fatalf("e.context gave %T (%+v), want a string", result, result)
	}
	if str.Value != "user" {
		t.Errorf("context = %q, want %q", str.Value, "user")
	}
}

// The other direction: a real mistake must still stop the program. A builtin
// that fails is a fault, and so is a language-level error, and neither may be
// mistaken for a value now that some errors are values.
func TestGenuineFaultsStillStopEvaluation(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"builtin failure", `let x = len(1); 99`, "argument to `len` not supported, got INTEGER"},
		{"unknown identifier", `nowhere`, "identifier not found: nowhere"},
		{"type mismatch mid-program", `5 + true; 99`, "type mismatch: INTEGER+BOOLEAN"},
		{"field access on a fault", `nowhere.message`, "identifier not found: nowhere"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errObj, ok := testEval(tt.input).(*object.Error)
			if !ok {
				t.Fatalf("evaluation did not fault; a mistake was treated as a value")
			}
			if errObj.Message != tt.want {
				t.Errorf("message = %q, want %q", errObj.Message, tt.want)
			}
		})
	}
}

// The fault type must not escape the package. Outside here an error is a value,
// and a caller handed a fault would have to know the difference to use it.
func TestEvalUnwrapsFaultsAtTheBoundary(t *testing.T) {
	if _, leaked := testEval(`nowhere`).(*fault); leaked {
		t.Fatal("Eval returned a fault; it must unwrap to a plain *object.Error")
	}
}

// Errors compare by what went wrong, not by where. Position is excluded
// deliberately: the VM stamps one and this engine does not, so comparing
// rendered forms would make equality depend on which engine ran the program.
func TestErrorEqualityIgnoresPosition(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{`error("a") == error("a")`, true},
		{`error("a") == error("b")`, false},
		{`error("a", "x") == error("a", "y")`, false},
		{`error("a") != error("b")`, true},
		{`error("a") == "ERROR:a"`, false},
		{`error("a", "c", {"n": 1}) == error("a", "c", {"n": 1})`, true},
		{`error("a", "c", {"n": 1}) == error("a", "c", {"n": 2})`, false},
	}
	for _, tt := range tests {
		result, ok := testEval(tt.input).(*object.Boolean)
		if !ok {
			t.Fatalf("%s gave %T, want a boolean", tt.input, result)
		}
		if result.Value != tt.want {
			t.Errorf("%s = %t, want %t", tt.input, result.Value, tt.want)
		}
	}
}
