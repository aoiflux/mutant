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
// TestWhileScopesItsBodyExactlyAsForDoes still asks the question it always
// asked, and now has the answer Go gives: a loop body is a scope, so a name
// declared inside one is gone after it, and a while and a for agree about that.
//
// It used to assert the two agreed by reading `inside` AFTER the loop and
// finding it. Both loops did find it, because no loop body was a scope -- so
// the test passed on the strength of the two engines being wrong in step. The
// name after the loop is now the whole assertion: both forms must refuse it,
// and refuse it in the same words.
func TestWhileScopesItsBodyExactlyAsForDoes(t *testing.T) {
	whileSrc := "let n = 0; while (n < 1) { let inside = 1; n = n + inside; } inside"
	forSrc := "for (let n = 0; n < 1; n = n + 1) { let inside = 1; } inside"

	whileMsg, whileRefused := compilerRefusesAName(whileSrc)
	forMsg, forRefused := compilerRefusesAName(forSrc)

	if !whileRefused || !forRefused {
		t.Fatalf("a loop body is a scope, so `inside` after the loop must not resolve: "+
			"while refused=%v (%q), for refused=%v (%q)", whileRefused, whileMsg, forRefused, forMsg)
	}
	if whileMsg != forMsg {
		t.Errorf("a while body and a for body are refused in different words:\n  while: %s\n  for:   %s",
			whileMsg, forMsg)
	}
}

// TestBothLoopsScopeTheirBodyWithoutLosingIt is the other half: the body is a
// scope, and scoping it must not stop the body from working. Each loop counts
// with a name of its own and the count survives, which is what distinguishes a
// scope from a wall.
func TestBothLoopsScopeTheirBodyWithoutLosingIt(t *testing.T) {
	for _, c := range []struct{ name, src, want string }{
		{"while", "let n = 0; let seen = 0; while (n < 3) { let step = 1; n = n + step; seen = seen + step; } seen", "INTEGER(3)"},
		{"for", "let seen = 0; for (let i = 0; i < 3; i = i + 1) { let step = 1; seen = seen + step; } seen", "INTEGER(3)"},
		// The body redeclares the name the header declared. Go allows this --
		// the body is a block nested inside the header's -- and the loop still
		// terminates, because the post section is compiled after the body's
		// scope has closed and increments the header's i. Before block scoping
		// this program did not terminate at all.
		{"for, body shadows the counter", "let hits = 0; for (let i = 0; i < 3; i = i + 1) { let i = 9; hits = hits + 1; } hits", "INTEGER(3)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			evaluated := normalize(evalViaEvaluator(c.src))
			vmObj, err := evalViaVM(t, c.src)
			if err != nil {
				t.Fatalf("VM refused the program: %v", err)
			}
			if compiled := normalize(vmObj); evaluated != compiled {
				t.Fatalf("engines disagree: evaluator %s, VM %s", evaluated, compiled)
			}
			if evaluated != c.want {
				t.Fatalf("both engines answered %s, want %s", evaluated, c.want)
			}
		})
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
