package parity

import (
	"testing"
)

// L-8 adds `while`. Both engines are asserted against the value rather than
// only against each other: a loop that runs one iteration too few or too many
// produces a plausible number, not an error, so agreeing on a wrong count is
// exactly the failure a pure parity check cannot see.
func TestWhileLoopSemantics(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// The condition is tested before the first iteration, so a body whose
		// condition starts false never runs.
		{"let n = 0; while (false) { n = n + 1; } n", "INTEGER(0)"},
		{"let n = 5; while (n < 5) { n = n + 1; } n", "INTEGER(5)"},

		// Ordinary counting.
		{"let n = 0; while (n < 5) { n = n + 1; } n", "INTEGER(5)"},
		{"let n = 0; let s = 0; while (n < 4) { n = n + 1; s = s + n; } s", "INTEGER(10)"},

		// break leaves immediately; the condition is not re-tested.
		{"let n = 0; while (true) { n = n + 1; if (n == 3) { break; } } n", "INTEGER(3)"},

		// continue goes back to the condition. In a for loop it would run the
		// post section first; a while has none, so the body itself has to make
		// progress or the loop hangs -- which is what this case pins.
		{"let n = 0; let s = 0; while (n < 6) { n = n + 1; if (n % 2 == 0) { continue; } s = s + n; } s", "INTEGER(9)"},

		// Nested, with break binding to the innermost loop only.
		{"let outer = 0; let hits = 0; while (outer < 3) { outer = outer + 1; let inner = 0; while (true) { inner = inner + 1; hits = hits + 1; if (inner == 2) { break; } } } hits", "INTEGER(6)"},

		// A while inside a function, so the local-slot path is covered too.
		{"let f = fn(limit) { let i = 0; while (i < limit) { i = i + 1; } return i; }; f(7)", "INTEGER(7)"},

		// return from inside the body leaves the function, not just the loop.
		{"let f = fn() { let i = 0; while (true) { i = i + 1; if (i == 4) { return i; } } return 0; }; f()", "INTEGER(4)"},

		// A loop over a collection, which is what `for…in` will replace.
		{"let xs = [3, 4, 5]; let i = 0; let sum = 0; while (i < len(xs)) { sum = sum + xs[i]; i = i + 1; } sum", "INTEGER(12)"},

		// Truthiness follows the same rule as `if`: the condition is not
		// required to be a boolean.
		{"let n = 3; while (n) { n = n - 1; } n", "INTEGER(0)"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			evaluated := normalize(evalViaEvaluator(tt.input))

			vmObj, vmErr := evalViaVM(t, tt.input)
			if vmErr != nil {
				t.Fatalf("VM refused %q: %v (evaluator gave %s)", tt.input, vmErr, evaluated)
			}
			compiled := normalize(vmObj)

			if evaluated != compiled {
				t.Fatalf("engines disagree on %q: evaluator %s, VM %s", tt.input, evaluated, compiled)
			}
			if evaluated != tt.want {
				t.Fatalf("both engines answered %s for %q, want %s", evaluated, tt.input, tt.want)
			}
		})
	}
}

// TestWhileScopesItsBodyExactlyAsForDoes is written against `for` rather than
// against a scoping rule, because the two engines do not agree about loop-body
// scope and never have:
//
//   - the evaluator gives each loop body an enclosed Environment, so a `let`
//     inside it is gone afterwards;
//   - the VM has function scopes only, so the same `let` compiles to the
//     enclosing slot and is readable after the loop.
//
// That divergence belongs to `for` and predates L-8. What must be true is that
// `while` does not add a *second*, different answer -- so each engine is
// compared against itself running the equivalent for loop, and the assertion
// holds whichever way the divergence is eventually resolved.
func TestWhileScopesItsBodyExactlyAsForDoes(t *testing.T) {
	whileSrc := "let n = 0; while (n < 1) { let inside = 1; n = n + inside; } inside"
	forSrc := "for (let n = 0; n < 1; n = n + 1) { let inside = 1; } inside"

	if got, want := normalize(evalViaEvaluator(whileSrc)), normalize(evalViaEvaluator(forSrc)); got != want {
		t.Errorf("evaluator scopes a while body differently from a for body: %s vs %s", got, want)
	}

	whileObj, whileErr := evalViaVM(t, whileSrc)
	forObj, forErr := evalViaVM(t, forSrc)
	if (whileErr == nil) != (forErr == nil) {
		t.Fatalf("VM scopes a while body differently from a for body: while %v, for %v", whileErr, forErr)
	}
	if whileErr == nil && normalize(whileObj) != normalize(forObj) {
		t.Errorf("VM scopes a while body differently from a for body: %s vs %s", normalize(whileObj), normalize(forObj))
	}
}

// TestWhileConditionIsReEvaluated is the whole difference between a loop and an
// if. It would pass trivially against a correct implementation and fail loudly
// against one that hoisted the condition out.
func TestWhileConditionIsReEvaluated(t *testing.T) {
	src := "let calls = 0; let bump = fn() { calls = calls + 1; return calls < 4; }; while (bump()) { } calls"

	evaluated := normalize(evalViaEvaluator(src))
	vmObj, err := evalViaVM(t, src)
	if err != nil {
		t.Fatalf("VM refused the program: %v", err)
	}
	compiled := normalize(vmObj)

	if evaluated != compiled {
		t.Fatalf("engines disagree: evaluator %s, VM %s", evaluated, compiled)
	}
	if evaluated != "INTEGER(4)" {
		t.Fatalf("both engines answered %s, want INTEGER(4)", evaluated)
	}
}
