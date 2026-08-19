package evaluator

import (
	"mutant/object"
	"testing"
)

func TestEvalCompoundAssignmentInteger(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"let i = 5; i += 3; i", 8},
		{"let i = 5; i -= 2; i", 3},
		{"let i = 4; i *= 3; i", 12},
		{"let i = 20; i /= 4; i", 5},
		{"let i = 17; i %= 5; i", 2},
		// the assignment expression itself yields the stored value
		{"let i = 5; i += 1", 6},
		// chained on subsequent lines
		{"let i = 1; i += 2; i += 3; i", 6},
	}

	for _, tt := range tests {
		testIntegerObject(t, testEval(tt.input), tt.expected)
	}
}

func TestEvalIncrementDecrement(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"let i = 0; i++; i", 1},
		{"let i = 0; i++; i++; i++; i", 3},
		{"let i = 10; i--; i", 9},
		{"let i = 5; i--; i--; i", 3},
	}

	for _, tt := range tests {
		testIntegerObject(t, testEval(tt.input), tt.expected)
	}
}

func TestEvalCompoundAssignmentFloat(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"let x = 1.5; x += 2.0; x", 3.5},
		{"let x = 3.0; x *= 2.0; x", 6.0},
		{"let x = 10.0; x /= 4.0; x", 2.5},
	}

	for _, tt := range tests {
		testFloatObject(t, testEval(tt.input), tt.expected)
	}
}

func TestEvalCompoundAssignmentString(t *testing.T) {
	result := testEval(`let s = "ab"; s += "cd"; s`)
	str, ok := result.(*object.String)
	if !ok {
		t.Fatalf("expected String, got %T (%v)", result, result)
	}
	if str.Value != "abcd" {
		t.Fatalf("expected \"abcd\", got %q", str.Value)
	}
}

// Compound-assigning an undefined variable is an error: there is no current
// value to fold with.
func TestEvalCompoundAssignmentUndefinedTargetErrors(t *testing.T) {
	result := testEval(`undefined_var += 1`)
	if _, ok := result.(*object.Error); !ok {
		t.Fatalf("expected an error assigning to an undefined variable, got %T (%v)", result, result)
	}
}
