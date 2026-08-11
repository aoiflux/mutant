package evaluator

import "testing"

// TestLogicalOperators covers && / || in the tree-walking evaluator: results,
// precedence, strict-boolean coercion, and short-circuit. The `boom` identifier
// is never defined; if the right operand of a short-circuiting operator were
// evaluated it would yield an error (not a boolean), failing testBooleanObject.
func TestLogicalOperators(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"true && true", true},
		{"true && false", false},
		{"false && true", false},
		{"true || false", true},
		{"false || false", false},

		// comparisons bind tighter than && / ||
		{"1 == 1 && 2 == 2", true},
		{"1 == 1 && 2 == 3", false},
		{"1 == 2 || 3 == 3", true},
		{"2 > 1 && 3 > 2", true},

		// && binds tighter than ||
		{"false || true && true", true},
		{"true && true && false", false},

		// non-boolean operands -> strict boolean result (via truthiness)
		{"5 && 3", true},
		{"0 || 0", false},

		// short-circuit: `boom` is undefined and must never be evaluated.
		{"false && boom", false},
		{"true || boom", true},
	}
	for _, tt := range tests {
		testBooleanObject(t, testEval(tt.input), tt.expected)
	}
}
