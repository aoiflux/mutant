package parity

import (
	"strings"
	"testing"
)

// L-8 phase 3 adds `match`. Both engines are asserted against the value rather
// than only against each other: an arm chain that takes the wrong branch
// produces a plausible value, not an error, so agreeing on a wrong answer is
// exactly the failure a pure parity check cannot see.
func TestMatchSemantics(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Arms are taken in source order, first match wins.
		{`match (2) { 1 => 10, 2 => 20, _ => 30 }`, "INTEGER(20)"},
		{`match (1) { 1 => 10, 1 => 20, _ => 30 }`, "INTEGER(10)"},

		// The wildcard catches what nothing else does, wherever it is written.
		{`match (9) { 1 => 10, 2 => 20, _ => 30 }`, "INTEGER(30)"},
		{`match (1) { _ => "any", 1 => "one" }`, `STRING("any")`},

		// `|` joins alternatives; each one is tested against the same subject.
		{`match (3) { 1 | 2 | 3 => "few", _ => "many" }`, `STRING("few")`},
		{`match (1) { 1 | 2 | 3 => "few", _ => "many" }`, `STRING("few")`},
		{`match (4) { 1 | 2 | 3 => "few", _ => "many" }`, `STRING("many")`},

		// Every literal kind the pattern grammar admits.
		{`match ("b") { "a" => 1, "b" => 2, _ => 3 }`, "INTEGER(2)"},
		{`match (1.5) { 1.5 => "f", _ => "n" }`, `STRING("f")`},
		{`match (false) { true => 1, false => 2 }`, "INTEGER(2)"},
		{`match (-1) { -1 => "neg", _ => "other" }`, `STRING("neg")`},

		// A match is an expression: it binds, it nests, it is an operand.
		{`let x = match (true) { true => 1, false => 2 }; x`, "INTEGER(1)"},
		{`match (1) { 1 => 7, _ => 8 } + 1`, "INTEGER(8)"},
		{`match (1) { 1 => match (2) { 2 => "in", _ => "no" }, _ => "out" }`, `STRING("in")`},
		{`let f = fn(n) { return match (n) { 0 => "zero", _ => "some" }; }; f(0)`, `STRING("zero")`},

		// A braced body runs statements and evaluates to its last expression.
		{`match (1) { 1 => { let y = 5; y * 2 }, _ => 0 }`, "INTEGER(10)"},
		{`let s = 0; match (1) { 1 => { s = s + 1; }, _ => 0 }; s`, "INTEGER(1)"},

		// A body that computes nothing produces null in both engines. The VM
		// reaches this by emitting OpNull for a body that leaves no value; the
		// evaluator by turning a valueless block result into NULL.
		{`match (1) { 1 => { let y = 5; }, _ => 0 }`, "NULL()"},
		{`match (1) { 1 => { }, _ => 0 }`, "NULL()"},
		{`match (2) { 1 => 1, _ => { let y = 5; } }`, "NULL()"},

		// The subject is evaluated exactly once, however many arms test it.
		{`let n = 0; let bump = fn() { n = n + 1; return 2; }; match (bump()) { 1 => 0, 2 => 0, _ => 0 }; n`, "INTEGER(1)"},

		// Enum variants, which is what match is mostly for.
		{`enum Status { Ok, Err }; match (Status.Err) { Status.Ok => 1, Status.Err => 2 }`, "INTEGER(2)"},
		{`enum S { A, B }; match (1) { S.A => "a", _ => "no" }`, `STRING("no")`},

		// Inside a function and inside a loop, so the local-slot path and the
		// repeated-evaluation path are both covered.
		{`let k = 2; let f = fn() { return match (k) { 1 => "a", 2 => "b", _ => "c" }; }; f()`, `STRING("b")`},
		{`let xs = [1, 2, 3]; let s = 0; for (x in xs) { s = s + match (x) { 1 => 10, _ => 1 }; } s`, "INTEGER(12)"},
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

// TestAnUnmatchedSubjectIsAnError is the decision behind OpMatchFail. A match
// is an expression, so falling off the end could only produce null -- and that
// null would flow on as though some arm had produced it. An enum gaining a
// variant later is exactly the case where every existing match would start
// doing that silently.
func TestAnUnmatchedSubjectIsAnError(t *testing.T) {
	input := `match (9) { 1 => 10, 2 => 20 }`

	if got := normalize(evalViaEvaluator(input)); got != "ERROR" {
		t.Errorf("the evaluator answered %s for an unmatched subject, want an error", got)
	}

	_, vmErr := evalViaVM(t, input)
	if vmErr == nil {
		t.Fatal("the VM produced a value for an unmatched subject")
	}
	// The value is named, because "no arm matched" without it sends the reader
	// back to the source to work out which value arrived.
	if !strings.Contains(vmErr.Error(), "9") {
		t.Errorf("the VM error %q does not name the unmatched value", vmErr)
	}
}

// TestAMatchArmAlwaysLeavesExactlyOneValue is the invariant behind the
// compiler's leaveOneValue, asserted where it can actually be seen.
//
// A body ending in an expression statement ends in an OpPop -- the statement
// pushed its value and threw it away -- so removing that pop turns the block
// back into the value it computed. A body ending in anything else computed no
// value, and a branch that pushes nothing while its siblings push one leaves
// everything after it reading one slot too deep. Binding the match and then
// reading the binding is what makes either mistake visible.
func TestAMatchArmAlwaysLeavesExactlyOneValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"a bare value", `let p = match (1) { 2 => 3, _ => 4 }; p`, "INTEGER(4)"},
		{"a block ending in a value", `let p = match (1) { 1 => { 3 }, _ => 4 }; p`, "INTEGER(3)"},
		{"a block ending in a let", `let p = match (1) { 1 => { let a = 3; }, _ => 4 }; p`, "NULL()"},
		{"an empty block", `let p = match (1) { 1 => { }, _ => 4 }; p`, "NULL()"},
		{"a block ending in a loop", `let p = match (1) { 1 => { while (false) { } }, _ => 4 }; p`, "NULL()"},
		{"alternatives", `let p = match (3) { 2 | 3 | 4 => 5, _ => 6 }; p`, "INTEGER(5)"},
		{"a block ending in a for", `let p = match (1) { 1 => { for (v in []) { } }, _ => 4 }; p`, "NULL()"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

// TestAWildcardMakesAMatchTotal is the other half: with a `_` there is no
// failure path at all, so the compiler emits no OpMatchFail and nothing can
// reach it.
func TestAWildcardMakesAMatchTotal(t *testing.T) {
	input := `match (9) { 1 => 10, _ => 20 }`
	if _, err := evalViaVM(t, input); err != nil {
		t.Fatalf("a match with a wildcard still failed: %v", err)
	}
}

// TestEnumEqualityIsTypedRatherThanRendered covers a hole `match` made
// reachable. Both engines used to fall through to comparing Inspect, and an
// enum renders as `Status.Ok(0)` -- so a string spelling that text compared
// equal to the variant itself. Bytes and errors each got a typed comparison for
// exactly this reason; enums never did.
func TestEnumEqualityIsTypedRatherThanRendered(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`enum Status { Ok, Err }; Status.Ok == "Status.Ok(0)"`, "BOOLEAN(false)"},
		{`enum Status { Ok, Err }; Status.Ok != "Status.Ok(0)"`, "BOOLEAN(true)"},
		{`enum Status { Ok, Err }; Status.Ok == Status.Ok`, "BOOLEAN(true)"},
		{`enum Status { Ok, Err }; Status.Ok == Status.Err`, "BOOLEAN(false)"},
		{`enum A { X }; enum B { X }; A.X == B.X`, "BOOLEAN(false)"},
		{`enum Status { Ok, Err }; Status.Ok == 0`, "BOOLEAN(false)"},

		// And the arm that made it matter: a string must not take an enum's arm.
		{`enum Status { Ok, Err }; match ("Status.Ok(0)") { Status.Ok => "took it", _ => "did not" }`, `STRING("did not")`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			evaluated := normalize(evalViaEvaluator(tt.input))

			vmObj, vmErr := evalViaVM(t, tt.input)
			if vmErr != nil {
				t.Fatalf("VM refused %q: %v", tt.input, vmErr)
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

// TestAnIfBranchAlsoLeavesExactlyOneValue covers two pre-existing defects that
// the same leaveOneValue now fixes. `if` decided whether its branch had
// produced a value by looking at the last instruction emitted, which was wrong
// in both directions:
//
//   - a branch ending in a `let` emitted no pop at all, so nothing was removed
//     and the branch pushed nothing where its sibling pushed one -- the VM then
//     underflowed on the very next pop;
//   - a branch ending in a `for (v in xs)` ended in the pop that drops the loop
//     cursor, which looked exactly like a value being discarded, so that pop
//     was removed and the cursor itself became the branch's value.
//
// Neither was reachable through `match` -- both predate it -- but the fix is
// the same one, so it is pinned here beside it.
func TestAnIfBranchAlsoLeavesExactlyOneValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"both branches value", `let p = if (true) { 3 } else { 4 }; p`, "INTEGER(3)"},
		{"consequence ends in a let", `let p = if (true) { let x = 1; } else { 4 }; p`, "NULL()"},
		{"alternative ends in a let", `let p = if (false) { 3 } else { let x = 1; }; p`, "NULL()"},
		{"consequence ends in a for-in", `let p = if (true) { for (v in []) { } } else { 4 }; p`, "NULL()"},
		{"alternative ends in a for-in", `let p = if (false) { 3 } else { for (v in []) { } }; p`, "NULL()"},
		{"an empty branch", `let p = if (true) { } else { 4 }; p`, "NULL()"},
		{"no alternative at all", `let p = if (false) { 3 }; p`, "NULL()"},
		// The statement form, which used to underflow before anything could
		// read the value.
		{"as a statement", `if (true) { let x = 1; } else { 20 } 7`, "INTEGER(7)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
