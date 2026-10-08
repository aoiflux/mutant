package parity

// `!` is the negation of truthiness, in both engines (M26-VM-007), and a call that
// produces no value is null rather than a Go nil (M26-EVL-020).
//
// The law, stated once: for every value x,
//
//	isTruthy(x) != isTruthy(!x)
//
// A parity test cannot be the gate here, and that is the thing worth knowing about
// this file. Both engines answered `!0` = false, so they AGREED on a wrong answer:
// a test that only asks whether the two engines match would have passed throughout.
// The engines diverged on exactly two of the thirty-odd values below. So the gate is
// the law, asked of each engine separately, and parity is an additional check rather
// than the check.
//
// Each engine is asked for truthiness the only way that cannot drift from the engine
// itself -- by running `if (x) { 1 } else { 0 }`, which consults the same isTruthy
// that `while`, `for`, `match`, `&&` and `||` consult. Nothing here reimplements the
// rule, so nothing here can be wrong about it in the same direction as the code.
//
// The second half of the table reaches each value the way a program would: through a
// variable, a return, an array element, a hash value, a parameter. The VM's `!` used
// to switch on pointer identity against global.False, and a rule like that holds or
// fails depending on whether the pointer survived the global store, the stack's
// encryptForStorage/decryptForUse round trip and the container. It survived all of
// them -- so identity was never the fault, and these rows are here to keep that
// measured rather than assumed.

import (
	"strings"
	"testing"
)

// bangCase is one value, reached as a program would reach it. prelude holds any
// statements the expression needs; expr is the value itself.
type bangCase struct {
	label   string
	prelude string
	expr    string
}

func bangCases() []bangCase {
	return []bangCase{
		// Literals: the whole falsy set, each beside a truthy neighbour.
		{"true", "", "true"},
		{"false", "", "false"},
		{"integer 0", "", "0"},
		{"integer 1", "", "1"},
		{"integer -1", "", "0 - 1"},
		{"float 0.0", "", "0.0"},
		{"float 1.5", "", "1.5"},
		{"the empty string", "", `""`},
		{"a one-letter string", "", `"a"`},

		// Strings that spell a keyword. Only a rule that compares rendered text
		// sees these, and the evaluator's did: `!"false"` was true there.
		{`the string "true"`, "", `"true"`},
		{`the string "false"`, "", `"false"`},
		{`the string "null"`, "", `"null"`},
		{`the string "0"`, "", `"0"`},
		{"a one-space string", "", `" "`},

		// Buffers. An empty buffer is falsy and renders as the empty string, which
		// is also how null renders -- the collision the evaluator's old rule relied
		// on without saying so.
		{"an empty buffer", `let eb, ee = string_to_bytes("", "raw");`, "eb"},
		{"a two-byte buffer", `let nb, ne = string_to_bytes("ab", "raw");`, "nb"},

		// Containers are truthy whether or not they hold anything.
		{"an empty array", "", "[]"},
		{"a one-element array", "", "[1]"},
		{"an empty hash", "", "{}"},
		{"a one-pair hash", "", "{1: 2}"},

		// null, which has no literal in this language.
		{"null from a hash miss", `let hm = {"a": 1};`, `hm["b"]`},
		{"null from a bare return", `let nf = fn() { return; };`, "nf()"},
		{"null from a valueless call", `let vf = fn() { let x = 1; };`, "vf()"},

		// The same values, reached through storage.
		{"false in a variable", "let vf2 = false;", "vf2"},
		{"0 in a variable", "let vz = 0;", "vz"},
		{"the empty string in a variable", `let vs = "";`, "vs"},
		{"false from a return", "let rf = fn() { return false; };", "rf()"},
		{"0 from a return", "let rz = fn() { return 0; };", "rz()"},
		{"false in an array", "", "[false][0]"},
		{"0 in an array", "", "[0][0]"},
		{"false under a key", `let kf = {"k": false};`, `kf["k"]`},
		{"false as a parameter", "let pf = fn(p) { return p; };", "pf(false)"},

		// Booleans that were computed rather than written.
		{"a computed true", "", "1 < 2"},
		{"a computed false", "", "2 < 1"},
		{"a computed false from ==", "", `"a" == "b"`},
	}
}

// bangEngine runs one program and renders the result; ERROR if the engine declined.
type bangEngine struct {
	name string
	run  func(t *testing.T, src string) string
}

func bangEngines() []bangEngine {
	return []bangEngine{
		{"evaluator", func(t *testing.T, src string) string {
			return normalize(evalViaEvaluator(src))
		}},
		{"vm", func(t *testing.T, src string) string {
			obj, err := evalViaVM(t, src)
			if err != nil {
				return "ERROR"
			}
			return normalize(obj)
		}},
	}
}

// bangTruth asks an engine whether a value is truthy, by asking the engine's own
// `if`. "T", "F", or the rendering if the program did not reach a branch.
func bangTruth(t *testing.T, e bangEngine, prelude, expr string) string {
	got := e.run(t, prelude+" if ("+expr+") { 1 } else { 0 }")
	switch got {
	case "INTEGER(1)":
		return "T"
	case "INTEGER(0)":
		return "F"
	}
	return got
}

// The law. A value and its negation cannot have the same truthiness, in either
// engine, for any value.
func TestBangIsTheNegationOfTruthiness(t *testing.T) {
	for _, tc := range bangCases() {
		for _, e := range bangEngines() {
			x := bangTruth(t, e, tc.prelude, tc.expr)
			notX := bangTruth(t, e, tc.prelude, "!("+tc.expr+")")

			if x != "T" && x != "F" {
				t.Errorf("%s: %s could not be tested for truthiness: %s", e.name, tc.label, x)
				continue
			}
			if notX != "T" && notX != "F" {
				t.Errorf("%s: !%s could not be tested for truthiness: %s", e.name, tc.label, notX)
				continue
			}
			if x == notX {
				t.Errorf("%s: %s and its negation are both %s -- `if (x)` and `if (!x)` take the same branch",
					e.name, tc.label, map[string]string{"T": "truthy", "F": "falsy"}[x])
			}
		}
	}
}

// `!` yields a boolean and nothing else, whatever it was given.
func TestBangAlwaysYieldsABoolean(t *testing.T) {
	for _, tc := range bangCases() {
		for _, e := range bangEngines() {
			got := e.run(t, tc.prelude+" !("+tc.expr+")")
			if !strings.HasPrefix(got, "BOOLEAN(") {
				t.Errorf("%s: !%s = %s, want a BOOLEAN", e.name, tc.label, got)
			}
		}
	}
}

// !!x has x's truthiness. This is the property a reader checks by hand, and it was
// false for 0: `!!0` was true.
func TestDoubleBangIsTheOriginalTruthiness(t *testing.T) {
	for _, tc := range bangCases() {
		for _, e := range bangEngines() {
			x := bangTruth(t, e, tc.prelude, tc.expr)
			want := "BOOLEAN(true)"
			if x == "F" {
				want = "BOOLEAN(false)"
			}
			if got := e.run(t, tc.prelude+" !!("+tc.expr+")"); got != want {
				t.Errorf("%s: !!%s = %s, but %s is %s so it must be %s",
					e.name, tc.label, got, tc.label,
					map[string]string{"T": "truthy", "F": "falsy"}[x], want)
			}
		}
	}
}

// Parity, which is the additional check rather than the gate: the two engines must
// answer the same thing. Before this change they differed on the empty string, an
// empty buffer and the string "false" -- the first two because the VM's identity
// rule missed them, the third because the evaluator's Inspect rule caught it by
// mistake.
func TestBothEnginesAgreeOnEveryBang(t *testing.T) {
	for _, tc := range bangCases() {
		src := tc.prelude + " !(" + tc.expr + ")"
		evalRes := normalize(evalViaEvaluator(src))
		vmObj, vmErr := evalViaVM(t, src)
		vmRes := normalize(vmObj)
		if vmErr != nil {
			vmRes = "ERROR"
		}
		if evalRes != vmRes {
			t.Errorf("engine divergence for !%s: evaluator=%s vm=%s", tc.label, evalRes, vmRes)
		}
	}
}

// A call that produces no value is null, in both engines (M26-EVL-020).
//
// eval returns a Go nil for a body that yields nothing, and applyFunction's
// user-function arm used to hand that nil to the program while its builtin arm two
// lines below guarded the same case. The nil then reached whatever touched the value
// next and panicked it, with no recover anywhere above: `mutant prog.mut` died with
// a Go stack trace at compile time, because this engine is what expands macros.
//
// The four body shapes below are the ones that produce no value. A body ending in a
// `let` is the one that matters -- it is how a function that works by side effect is
// written, and it needs no unusual input to reach.
func TestACallThatProducesNoValueIsNull(t *testing.T) {
	bodies := []struct{ what, body string }{
		{"an empty body", ``},
		{"a body ending in a let", `let x = 1;`},
		{"a body that works then lets", `let y = 1; let x = 2;`},
		{"a body ending in a multi-let", `let a, b = 1, 2;`},
	}

	// Each use is a place the nil used to arrive and be dereferenced.
	uses := []struct{ what, expr, want string }{
		{"type_of", "type_of(V)", `STRING("NULL")`},
		{"bang", "!(V)", "BOOLEAN(true)"},
		{"double bang", "!!(V)", "BOOLEAN(false)"},
		{"equality", "V == 1", "BOOLEAN(false)"},
		{"bound to a name", "let bound = V; type_of(bound)", `STRING("NULL")`},
		{"as an argument", "let id = fn(p) { return type_of(p); }; id(V)", `STRING("NULL")`},
		{"as a condition", "if (V) { 1 } else { 0 }", "INTEGER(0)"},
		{"in an array", "len([V])", "INTEGER(1)"},
	}

	for _, b := range bodies {
		for _, u := range uses {
			src := "let f = fn() { " + b.body + " }; " +
				strings.Replace(u.expr, "V", "f()", 1)
			for _, e := range bangEngines() {
				if got := e.run(t, src); got != u.want {
					t.Errorf("%s: %s with %s gave %s, want %s",
						e.name, u.what, b.what, got, u.want)
				}
			}
		}
	}
}

// A loop whose condition is a valueless call must not run, and must stop.
//
// This was not a wrong answer in the evaluator, it was a hang: a nil condition was
// truthy, nothing in the body could change that, and the engine that runs macro
// expansion is the one that never returned. The VM ran the body zero times.
func TestAValuelessCallIsNotALoopCondition(t *testing.T) {
	for _, e := range bangEngines() {
		got := e.run(t, `let f = fn() { let x = 1; }; let n = 0; while (f()) { n = n + 1; } n`)
		if got != "INTEGER(0)" {
			t.Errorf("%s: while (valueless call) ran the body: n = %s, want INTEGER(0)", e.name, got)
		}
	}
}
