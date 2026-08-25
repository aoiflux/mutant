package evaluator

import (
	"strings"
	"testing"

	"mutant/object"
)

// Two bugs lived here, both reachable from a shipped example
// (examples/macros/macro_quote_unquote_basics.mut, which did not compile):
//
//  1. ast.Modify had no *CallExpression case, so the walk never entered a
//     call's arguments. A macro used as an argument -- `putln(emit_literal())`
//     -- was therefore never expanded, and since DefineMacros had already
//     removed the definition, it reached codegen as "undefined variable". The
//     same macro bound with `let x = emit_literal();` worked, which is what
//     made it look like a macro problem rather than a traversal one.
//
//  2. Expansion rewrote the macro body in place. quote(...) runs ast.Modify
//     over the quoted node to substitute the unquoted arguments, and that node
//     belongs to the macro -- a template every call re-uses. The first call's
//     arguments were baked in, so every later call replayed them.

func expandSource(t *testing.T, source string) string {
	t.Helper()

	program := testParseProgram(source)
	env := object.NewEnvironment()
	DefineMacros(program, env)
	expanded, err := ExpandMacros(program, env)
	if err != nil {
		t.Fatalf("expansion failed: %s", err)
	}
	return expanded.String()
}

// Wherever a macro call can appear, expansion has to reach it. Each case is a
// position ast.Modify used to walk straight past.
func TestMacrosExpandInEveryCallPosition(t *testing.T) {
	const definitions = `let seven = macro() { quote(7); };
let add = macro(a, b) { quote(unquote(a) + unquote(b)); };
`

	cases := []struct {
		name string
		use  string
	}{
		{"call argument", `putln(seven());`},
		{"nested call argument", `putln(putf(seven()));`},
		{"argument among others", `putln("n = ", seven(), "!");`},
		{"callee position", `[fn(x) { x; }][seven() - 7](1);`},
		{"array element", `let xs = [seven()];`},
		{"index expression", `let x = [1,2,3,4,5,6,7,8][seven()];`},
		{"assignment value", `let x = 0; x = seven();`},
		{"for condition", `for (let i = 0; i < seven(); i = i + 1) { putln(i); }`},
		{"for post", `for (let i = 0; i < 3; i = i + seven()) { putln(i); }`},
		{"for body", `for (let i = 0; i < 3; i = i + 1) { putln(seven()); }`},
		{"if condition", `if (seven() > 1) { putln("yes"); };`},
		{"nested macro argument", `putln(add(seven(), 1));`},
		{"struct literal field", `struct P { x; y; } let p = P{x: seven(), y: 1};`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expanded := expandSource(t, definitions+tc.use)
			if strings.Contains(expanded, "seven(") {
				t.Fatalf("the macro call survived expansion: %s", expanded)
			}
			if !strings.Contains(expanded, "7") {
				t.Fatalf("expansion produced no 7: %s", expanded)
			}
		})
	}
}

// The regression that matters most: a macro is a template, so calling it twice
// must expand it twice, against each call's own arguments.
func TestMacroExpandsFreshlyOnEveryCall(t *testing.T) {
	expanded := expandSource(t, `let add = macro(a, b) { quote(unquote(a) + unquote(b)); };
let first = add(3, 9);
let second = add(100, 5);
let third = add(1, 1);
`)

	for _, want := range []string{"(3 + 9)", "(100 + 5)", "(1 + 1)"} {
		if !strings.Contains(expanded, want) {
			t.Fatalf("expansion lost %s -- the macro body was rewritten in place: %s", want, expanded)
		}
	}
}

// The same thing where it was originally seen: the second call substituted an
// identifier rather than a literal, and got the first call's literals back.
func TestMacroDoesNotReplayTheFirstCallsArguments(t *testing.T) {
	expanded := expandSource(t, `let add = macro(a, b) { quote(unquote(a) + unquote(b)); };
putln(add(3, 9));
let dynamic = 100;
putln(add(dynamic, 5));
`)

	if !strings.Contains(expanded, "(dynamic + 5)") {
		t.Fatalf("the second expansion did not use its own arguments: %s", expanded)
	}
	if strings.Count(expanded, "(3 + 9)") != 1 {
		t.Fatalf("the first expansion's arguments leaked into another call site: %s", expanded)
	}
}

// Expanding must not consume the macro. A definition that survives one call has
// to behave identically on the next, including in a different position.
func TestMacroBodySurvivesExpansion(t *testing.T) {
	program := testParseProgram(`let add = macro(a, b) { quote(unquote(a) + unquote(b)); };
add(1, 2);
`)
	env := object.NewEnvironment()
	DefineMacros(program, env)

	stored, ok := env.Get("add")
	if !ok {
		t.Fatal("the macro was not defined")
	}
	macro, ok := stored.(*object.Macro)
	if !ok {
		t.Fatalf("expected a macro, got %T", stored)
	}
	before := macro.Body.String()

	if _, err := ExpandMacros(program, env); err != nil {
		t.Fatalf("expansion failed: %s", err)
	}

	if after := macro.Body.String(); after != before {
		t.Fatalf("expansion rewrote the macro body:\nbefore %s\nafter  %s", before, after)
	}
}

// Macros nest: an inner call is expanded before the outer one sees it, because
// ast.Modify is bottom-up.
func TestNestedMacroCallsExpandInnermostFirst(t *testing.T) {
	expanded := expandSource(t, `let double = macro(x) { quote(unquote(x) + unquote(x)); };
let result = double(double(3));
`)

	if strings.Contains(expanded, "double(") {
		t.Fatalf("a nested macro call survived expansion: %s", expanded)
	}
	if !strings.Contains(expanded, "3") {
		t.Fatalf("expansion lost the argument: %s", expanded)
	}
}

// A macro may produce a call to another macro. ast.Modify does not walk into
// what it has just substituted, so a single pass left that call in the tree and
// the compiler reported it as an undefined variable. Expansion repeats until
// nothing changes.
func TestMacroGeneratedMacroCallsAreExpanded(t *testing.T) {
	expanded := expandSource(t, `let double = macro(x) { quote(unquote(x) * 2); };
let doubleThenAdd = macro(x) { quote(double(unquote(x)) + 1); };
let result = doubleThenAdd(5);
`)

	if strings.Contains(expanded, "double(") {
		t.Fatalf("a macro-generated macro call survived expansion: %s", expanded)
	}
	if !strings.Contains(expanded, "((5 * 2) + 1)") {
		t.Fatalf("expansion did not settle on the expected source: %s", expanded)
	}
}

// Three levels deep, to prove the loop repeats rather than running a fixed
// second pass.
func TestMacroExpansionRepeatsUntilItSettles(t *testing.T) {
	expanded := expandSource(t, `let a = macro(x) { quote(unquote(x) + 1); };
let b = macro(x) { quote(a(unquote(x)) + 2); };
let c = macro(x) { quote(b(unquote(x)) + 3); };
let result = c(0);
`)

	for _, name := range []string{"a(", "b(", "c("} {
		if strings.Contains(expanded, name) {
			t.Fatalf("macro call %s survived expansion: %s", name, expanded)
		}
	}
}

// A macro that emits a call to itself never settles. The loop has to stop and
// say so rather than run until the process is killed.
func TestSelfExpandingMacroIsReported(t *testing.T) {
	program := testParseProgram(`let loopy = macro(x) { quote(loopy(unquote(x))); };
let y = loopy(1);
`)
	env := object.NewEnvironment()
	DefineMacros(program, env)

	_, err := ExpandMacros(program, env)
	if err == nil {
		t.Fatal("a self-expanding macro was accepted")
	}
	if !strings.Contains(err.Error(), "did not settle") {
		t.Fatalf("error does not explain the runaway expansion: %s", err)
	}
}
