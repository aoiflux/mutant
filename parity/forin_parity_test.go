package parity

import (
	"strings"
	"testing"
)

// The `for (x in xs)` half of L-8. Asserted against values, not merely against
// each other: a loop that visits the wrong half of a pair, or visits a hash in
// a different order on each run, produces a plausible answer rather than an
// error.
func TestForInSemantics(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// One binding over an array yields elements, not indices.
		{"let s = 0; for (v in [1, 2, 3]) { s = s + v; } s", "INTEGER(6)"},
		{"let last = 0; for (v in [7, 8, 9]) { last = v; } last", "INTEGER(9)"},

		// Two bindings yield index and element, in that order.
		{"let s = 0; for (i, v in [10, 20, 30]) { s = s + i; } s", "INTEGER(3)"},
		{"let s = 0; for (i, v in [10, 20, 30]) { s = s + v; } s", "INTEGER(60)"},
		{"let s = \"\"; for (i, v in [\"a\", \"b\"]) { s = s + \"${i}${v}\"; } s", `STRING("0a1b")`},

		// An empty collection runs the body zero times.
		{"let n = 0; for (v in []) { n = n + 1; } n", "INTEGER(0)"},
		{"let n = 0; for (v in {}) { n = n + 1; } n", "INTEGER(0)"},
		{"let n = 0; for (c in \"\") { n = n + 1; } n", "INTEGER(0)"},

		// One binding over a hash yields keys; two yield key and value.
		{"let ks = \"\"; for (k in {\"b\": 2, \"a\": 1}) { ks = ks + k; } ks", `STRING("ab")`},
		{"let s = 0; for (k, v in {\"b\": 2, \"a\": 1}) { s = s + v; } s", "INTEGER(3)"},

		// A string yields characters, a buffer yields byte values. This is the
		// distinction the bytes type exists for: iterating text by byte would
		// hand back half a rune.
		{"let s = \"\"; for (c in \"abc\") { s = s + c; } s", `STRING("abc")`},
		{"let n = 0; for (c in \"héllo\") { n = n + 1; } n", "INTEGER(5)"},
		// hex_decode_bytes returns (value, err), so the buffer is destructured
		// out first -- iterating the pair itself is refused, and rightly.
		{"let buf, e = hex_decode_bytes(\"01ff\"); let s = 0; for (b in buf) { s = s + b; } s", "INTEGER(256)"},

		// range() is how the roadmap's third collection kind is spelled; it is
		// already a builtin returning an array, so it needs no new syntax.
		{"let s = 0; for (n in range(0, 5)) { s = s + n; } s", "INTEGER(10)"},
		{"let s = 0; for (n in range(0, 10, 3)) { s = s + n; } s", "INTEGER(18)"},

		// break and continue.
		{"let s = 0; for (v in [1, 2, 3, 4]) { if (v == 3) { break; } s = s + v; } s", "INTEGER(3)"},
		{"let s = 0; for (v in [1, 2, 3, 4]) { if (v % 2 == 0) { continue; } s = s + v; } s", "INTEGER(4)"},

		// Nested, including over the same collection twice, which is what makes
		// the cursor a runtime object rather than compiler bookkeeping.
		{"let n = 0; let xs = [1, 2, 3]; for (a in xs) { for (b in xs) { n = n + 1; } } n", "INTEGER(9)"},
		{"let s = 0; let xs = [1, 2]; for (a in xs) { for (b in xs) { s = s + a * b; } } s", "INTEGER(9)"},

		// Inside a function, so the local-slot path is covered.
		{"let f = fn(xs) { let s = 0; for (v in xs) { s = s + v; } return s; }; f([4, 5, 6])", "INTEGER(15)"},

		// return from inside the loop leaves the function.
		{"let f = fn(xs) { for (v in xs) { if (v > 1) { return v; } } return 0; }; f([1, 2, 3])", "INTEGER(2)"},

		// The binding is readable after the loop and holds the last value, the
		// same way a for loop's counter is. Pinned so it cannot change silently.
		{"let last = 0; for (v in [1, 2, 3]) { last = v; } last", "INTEGER(3)"},

		// An expression, not just a name, may be iterated.
		{"let s = 0; for (v in [1, 2, 3]) { s = s + v; } for (v in [10]) { s = s + v; } s", "INTEGER(16)"},
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

// TestHashIterationOrderMatchesInspect is decision 5. Hash pairs live in a Go
// map, whose range order differs run to run, and Hash.Inspect already sorts for
// exactly that reason. If iteration used the raw map order instead, a program
// that printed a hash and a program that looped over it would disagree about
// what order the hash is in -- and the loop's own output would differ between
// two runs of the same program on the same input.
func TestHashIterationOrderMatchesInspect(t *testing.T) {
	const src = `let h = {"delta": 4, "alpha": 1, "charlie": 3, "bravo": 2};
let walked = "";
for (k in h) { walked = walked + k + " "; }
walked`

	first := normalize(evalViaEvaluator(src))
	if first != `STRING("alpha bravo charlie delta ")` {
		t.Fatalf("evaluator walked the hash as %s, want sorted key order", first)
	}

	vmObj, err := evalViaVM(t, src)
	if err != nil {
		t.Fatalf("VM refused the program: %v", err)
	}
	if got := normalize(vmObj); got != first {
		t.Fatalf("engines disagree on hash order: evaluator %s, VM %s", first, got)
	}

	// Run it repeatedly: one agreeing pair could be a coincidence of one map
	// layout, and the failure this pins is precisely an order that varies.
	for i := range 12 {
		again, err := evalViaVM(t, src)
		if err != nil {
			t.Fatalf("VM refused the program on run %d: %v", i, err)
		}
		if got := normalize(again); got != first {
			t.Fatalf("run %d walked the hash as %s, want %s -- the order is not stable", i, got, first)
		}
	}
}

// TestForInRefusesWhatItCannotIterate keeps the failure loud. Quietly running
// the body zero times for an integer would read as "the collection was empty".
func TestForInRefusesWhatItCannotIterate(t *testing.T) {
	for _, src := range []string{
		"for (v in 42) { }",
		"for (v in true) { }",
		"for (v in fn() { 1 }) { }",
	} {
		evaluated := normalize(evalViaEvaluator(src))
		if !strings.HasPrefix(evaluated, "ERROR") {
			t.Errorf("evaluator accepted %q, answering %s", src, evaluated)
		}

		if _, err := evalViaVM(t, src); err == nil {
			t.Errorf("VM accepted %q", src)
		}
	}
}

// TestForInCursorSurvivesAnInnerLoop is the reason the cursor is a value on the
// stack rather than state on the compiler: two loops over the same collection,
// with the inner one running to exhaustion, must not disturb the outer one.
func TestForInCursorSurvivesAnInnerLoop(t *testing.T) {
	src := `let xs = [1, 2, 3];
let seen = "";
for (a in xs) {
    for (b in xs) { }
    seen = seen + "${a}";
}
seen`

	evaluated := normalize(evalViaEvaluator(src))
	vmObj, err := evalViaVM(t, src)
	if err != nil {
		t.Fatalf("VM refused the program: %v", err)
	}
	compiled := normalize(vmObj)

	if evaluated != compiled {
		t.Fatalf("engines disagree: evaluator %s, VM %s", evaluated, compiled)
	}
	if evaluated != `STRING("123")` {
		t.Fatalf("both engines answered %s, want STRING(\"123\")", evaluated)
	}
}

// TestForInDoesNotLeakTheStack pins that every iteration is stack-neutral. The
// cursor sits underneath the body's working values for the whole loop, so a
// body that left one value behind per iteration would be read as the cursor on
// the next pass. A long loop is the cheapest way to catch that.
func TestForInDoesNotLeakTheStack(t *testing.T) {
	src := `let s = 0;
for (v in range(0, 20000)) { s = s + v; }
s`

	vmObj, err := evalViaVM(t, src)
	if err != nil {
		t.Fatalf("VM refused a 20000-iteration loop: %v", err)
	}
	if got := normalize(vmObj); got != "INTEGER(199990000)" {
		t.Fatalf("answered %s, want INTEGER(199990000)", got)
	}
}
