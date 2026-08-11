package vm

import "testing"

// TestLogicalOperators covers && / || in the compiler+VM path: results,
// precedence (comparisons bind tighter than &&/||, and && binds tighter than
// ||), strict-boolean coercion of truthy/falsy operands, and short-circuit.
func TestLogicalOperators(t *testing.T) {
	tests := []vmTestCase{
		{"true && true", true},
		{"true && false", false},
		{"false && true", false},
		{"false && false", false},
		{"true || false", true},
		{"false || true", true},
		{"false || false", false},
		{"true || true", true},

		// comparisons bind tighter than && / ||
		{"1 == 1 && 2 == 2", true},
		{"1 == 1 && 2 == 3", false},
		{"1 == 2 || 3 == 3", true},
		{"2 > 1 && 3 > 2", true},

		// && binds tighter than ||
		{"false || true && true", true},
		{"true && false || true", true},

		// chaining
		{"true && true && false", false},
		{"false || false || true", true},

		// non-boolean operands -> strict boolean result (via truthiness)
		{"5 && 3", true},
		{"0 || 0", false},
		{`"" || "x"`, true},

		// short-circuit: the right operand would error (integer division by zero)
		// if evaluated, so these passing at all proves it is skipped.
		{"false && (1 / 0)", false},
		{"true || (1 / 0)", true},
	}
	runVMTests(t, tests)
}
