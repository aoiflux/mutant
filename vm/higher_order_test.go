package vm

import (
	"testing"

	"mutant/object"
)

func TestHigherOrderBuiltins(t *testing.T) {
	cases := []struct {
		input    string
		expected interface{}
	}{
		// Core operations.
		{`map([1, 2, 3], fn(x) { x * 2 })`, []int{2, 4, 6}},
		{`filter([1, 2, 3, 4], fn(x) { x % 2 == 0 })`, []int{2, 4}},
		{`reduce([1, 2, 3, 4], fn(acc, x) { acc + x }, 0)`, 10},
		{`each([1, 2, 3], fn(x) { x })`, &object.Null{}},
		{`sort_by([3, 1, 2], fn(x) { x })`, []int{1, 2, 3}},

		// Two-parameter callbacks receive the index.
		{`map([10, 20, 30], fn(x, i) { x + i })`, []int{10, 21, 32}},
		{`filter([5, 6, 7, 8], fn(x, i) { i % 2 == 0 })`, []int{5, 7}},

		// Closures see globals during re-entry.
		{`let n = 100; map([1, 2, 3], fn(x) { x + n })`, []int{101, 102, 103}},

		// Free-variable capture survives the bridge (OpGetFree inside CallClosureSync).
		{`let adder = fn(n) { fn(x) { x + n } }; map([1, 2, 3], adder(10))`, []int{11, 12, 13}},

		// Nested higher-order calls (re-entrant CallClosureSync).
		{`map([1, 2], fn(x) { reduce([1, 1], fn(a, b) { a + b }, x) })`, []int{3, 4}},
		{`reduce(map([1, 2, 3], fn(x) { x * x }), fn(a, b) { a + b }, 0)`, 14},

		// Composes with the existing collection builtins.
		{`len(filter([1, 2, 3, 4, 5], fn(x) { x > 2 }))`, 3},

		// Argument validation surfaces as catchable errors (not aborts).
		{`map(5, fn(x) { x })`, &object.Error{Message: "map: first argument must be ARRAY, got INTEGER"}},
		{`filter([1], 7)`, &object.Error{Message: "filter: second argument must be a function, got INTEGER"}},
		{`reduce([1], fn(a, b) { a }, 0, 9)`, &object.Error{Message: "reduce: want 3 arguments (array, function, initial), got 4"}},
	}

	for _, tc := range cases {
		machine, err := runEncryptedVM(tc.input)
		if err != nil {
			t.Fatalf("%s -> vm error: %s", tc.input, err)
		}
		testExpectedObject(t, tc.expected, machine.LastPoppedStackElement())
	}
}

// TestHigherOrderClosureRuntimeErrorPropagates confirms that a runtime error
// inside a callback aborts the run (as a direct call would), rather than being
// silently swallowed by the bridge.
func TestHigherOrderClosureRuntimeErrorPropagates(t *testing.T) {
	if _, err := runEncryptedVM(`map([1, 0], fn(x) { 1 / x })`); err == nil {
		t.Fatal("expected a runtime error to propagate from the map callback")
	}
}
