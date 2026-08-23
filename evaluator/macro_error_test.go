package evaluator

import (
	"strings"
	"testing"

	"mutant/object"
)

// Every case here used to take the process down rather than report anything.
// Three of them panicked inside the compiler with a Go stack trace; two got
// further and planted a nil in the AST, which the compiler happily emitted and
// the VM died on with "index out of range [-1]" -- a whole phase away from the
// macro that caused it.
//
// A macro is source a user writes, so getting it wrong has to be a compiler
// error like any other.

func expandExpectingError(t *testing.T, source string) string {
	t.Helper()

	program := testParseProgram(source)
	env := object.NewEnvironment()
	DefineMacros(program, env)

	expanded, err := ExpandMacros(program, env)
	if err == nil {
		t.Fatalf("expansion succeeded; expected an error.\nsource:   %s\nexpanded: %s", source, expanded.String())
	}
	return err.Error()
}

func TestMacroErrorsAreReportedNotPanicked(t *testing.T) {
	cases := []struct {
		name   string
		source string
		want   string
	}{
		{
			"body does not return a quote",
			`let bad = macro() { 5; };
bad();`,
			"macro bad must return quote(...), got INTEGER",
		},
		{
			"body returns nothing quotable",
			`let bad = macro() { "text"; };
bad();`,
			"macro bad must return quote(...), got STRING",
		},
		{
			"too few arguments",
			`let add = macro(a, b) { quote(unquote(a) + unquote(b)); };
add(1);`,
			"wrong number of arguments. want=2, got=1",
		},
		{
			"too many arguments",
			`let one = macro(a) { quote(unquote(a)); };
one(1, 2);`,
			"wrong number of arguments. want=1, got=2",
		},
		{
			"quote with no expression",
			`let bad = macro() { quote(); };
bad();`,
			"quote takes exactly one expression, got 0",
		},
		{
			"unquote with no expression",
			`let bad = macro() { quote(unquote()); };
bad();`,
			"unquote takes exactly one expression, got 0",
		},
		{
			"unquote of a value with no source form",
			`let bad = macro() { quote(unquote([1, 2, 3])); };
bad();`,
			"ARRAY has no source form",
		},
		{
			"unquote of an unknown identifier",
			`let bad = macro() { quote(unquote(nowhere)); };
bad();`,
			"identifier not found: nowhere",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := expandExpectingError(t, tc.source)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("error does not explain the problem.\ngot:  %s\nwant substring: %s", got, tc.want)
			}
		})
	}
}

// The error has to name the macro. Expansion happens before any line
// information survives into the compiler's message, so the name is the only
// thing pointing at which macro to go and look at.
func TestMacroErrorNamesTheMacro(t *testing.T) {
	got := expandExpectingError(t, `let alpha = macro() { quote(1); };
let beta = macro() { 2; };
putln(alpha(), beta());`)

	if !strings.Contains(got, "beta") {
		t.Fatalf("the error does not name the failing macro: %s", got)
	}
	if strings.Contains(got, "alpha") {
		t.Fatalf("the error blames the macro that worked: %s", got)
	}
}

// unquote splices a computed value back into source. Anything with a literal
// spelling has to make that trip; a string and a float used to become nil.
func TestUnquoteConvertsEveryLiteralValue(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"integer", `quote(unquote(1 + 2));`, "3"},
		{"float", `quote(unquote(1.5 + 1.0));`, "2.5"},
		{"string", `quote(unquote("a" + "b"));`, `"ab"`},
		{"boolean", `quote(unquote(1 > 2));`, "false"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expanded := expandSource(t, "let m = macro() { "+tc.body+" };\nlet x = m();\n")
			if !strings.Contains(expanded, tc.want) {
				t.Fatalf("unquote did not produce %s: %s", tc.want, expanded)
			}
		})
	}
}

// A failed expansion must not hand back a half-rewritten program: the caller
// compiles whatever it is given, and a partially expanded tree is exactly the
// nil-argument shape that killed the VM.
func TestFailedExpansionReturnsNoProgram(t *testing.T) {
	program := testParseProgram(`let good = macro() { quote(1); };
let bad = macro() { 2; };
putln(good(), bad());`)
	env := object.NewEnvironment()
	DefineMacros(program, env)

	expanded, err := ExpandMacros(program, env)
	if err == nil {
		t.Fatal("expansion of a broken macro succeeded")
	}
	if expanded != nil {
		t.Fatalf("a failed expansion still returned a tree: %s", expanded.String())
	}
}
