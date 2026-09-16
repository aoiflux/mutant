package evaluator

import (
	"strings"
	"testing"

	"mutant/object"
)

// TestUnquoteInsideAHoleExpands pins that a ${...} hole is an ordinary
// expression as far as the macro machinery is concerned. Without an arm in
// ast.Modify the unquote would survive expansion and the program would fail
// with "undefined variable: unquote" a long way from the macro.
func TestUnquoteInsideAHoleExpands(t *testing.T) {
	program := testParseProgram(
		`let banner = macro(name) { quote(putln("[${ unquote(name) }] ready")); };
		 banner("scan");`)

	env := object.NewEnvironment()
	DefineMacros(program, env)
	expanded, err := ExpandMacros(program, env)
	if err != nil {
		t.Fatalf("expansion failed: %s", err)
	}

	printed := expanded.String()
	if strings.Contains(printed, "unquote") {
		t.Errorf("unquote survived expansion: %s", printed)
	}
}

// TestEvalJoinsTemplateParts keeps the two engines honest about what a hole
// produces. The evaluator only runs macro bodies now, but a macro that builds a
// message out of its arguments is exactly the kind anybody writes, so it has to
// agree with the VM's OpConcat.
func TestEvalJoinsTemplateParts(t *testing.T) {
	cases := []struct{ src, want string }{
		{`let h = "db01"; "host=${h}";`, "host=db01"},
		{`let n = 7; "n=${n}";`, "n=7"},
		{`let ok = false; "${ok}";`, "false"},
		{`"${ 2 + 3 }";`, "5"},
	}

	for _, tc := range cases {
		result := Eval(testParseProgram(tc.src), object.NewEnvironment())
		str, isString := result.(*object.String)
		if !isString {
			t.Fatalf("%s evaluated to %T (%v), want a string", tc.src, result, result)
		}
		if str.Value != tc.want {
			t.Errorf("%s evaluated to %q, want %q", tc.src, str.Value, tc.want)
		}
	}
}
