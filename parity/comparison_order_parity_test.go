package parity

import "testing"

// The two engines have to agree about WHEN each operand of a comparison runs,
// not only about the answer. `<` and `<=` were compiled as the greater family
// with the operands in the other order -- `a < b` as `b > a` -- so the VM ran
// the right operand first while the evaluator, which is the engine macro
// expansion computes an `unquote` with, ran the left one first. One expression
// then had two meanings: `next() < next()` was false in the VM and true in the
// evaluator (M26-CMP-005).
//
// TestMacroExpansionMatchesDirectCompilation already compares the two engines
// on `2 < 3` and `2 <= 2`, and could not catch this: two literals have no side
// effects to order. The order has to be made observable, which is what the
// counter and the log below are for. It is pinned against the evaluator
// directly rather than through an expansion because the macro environment is a
// fresh one -- it cannot see the program's own `next`, so the side effect has
// to be driven on each engine in turn.
func TestComparisonOperandsRunLeftToRightInBothEngines(t *testing.T) {
	// next returns 1, then 2, so the answer reports the order it was called
	// in: left to right compares 1 with 2, right to left compares 2 with 1.
	const counter = "let n = 0; let next = fn() { n = n + 1; return n; }; "

	for _, tt := range []struct {
		operator string
		want     string
	}{
		{"<", "BOOLEAN(true)"},
		{"<=", "BOOLEAN(true)"},
		{">", "BOOLEAN(false)"},
		{">=", "BOOLEAN(false)"},
	} {
		input := counter + "next() " + tt.operator + " next();"

		viaVM, err := evalViaVM(t, input)
		if err != nil {
			t.Fatalf("%s: the VM declined to answer: %s", input, err)
		}
		if got := normalize(viaVM); got != tt.want {
			t.Errorf("VM: %s = %s, want %s -- the left operand runs first", input, got, tt.want)
		}
		if got := normalize(evalViaEvaluator(input)); got != tt.want {
			t.Errorf("evaluator: %s = %s, want %s -- the left operand runs first", input, got, tt.want)
		}
	}
}

// The order itself, recorded rather than inferred from an answer: each operand
// appends its own name as it runs, so the value left behind spells the order
// the two were called in. This is the form the defect was reported in, and it
// stays readable whatever the comparison itself decides.
func TestComparisonOperandsAreCalledInSourceOrder(t *testing.T) {
	for _, operator := range []string{"<", "<=", ">", ">="} {
		input := `let log = ""; ` +
			`let a = fn() { log = log + "a"; return 1; }; ` +
			`let b = fn() { log = log + "b"; return 2; }; ` +
			`a() ` + operator + ` b(); ` +
			`log;`

		viaVM, err := evalViaVM(t, input)
		if err != nil {
			t.Fatalf("%s: the VM declined to answer: %s", input, err)
		}
		if got := normalize(viaVM); got != `STRING("ab")` {
			t.Errorf(`VM: a() %s b() called its operands in order %s, want STRING("ab")`, operator, got)
		}
		if got := normalize(evalViaEvaluator(input)); got != `STRING("ab")` {
			t.Errorf(`evaluator: a() %s b() called its operands in order %s, want STRING("ab")`, operator, got)
		}
	}
}
