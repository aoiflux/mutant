package vm

import (
	"testing"

	"mutant/compiler"
)

// runOneFile compiles and runs one file's worth of source with no modules, the
// way the REPL and every single-file program do.
func runOneFile(t *testing.T, src string) *VM {
	t.Helper()

	comp := compiler.New()
	if err := comp.Compile(parse(src)); err != nil {
		t.Fatalf("compiling %s: %v", src, err)
	}
	machine, err := runSealed(t, comp.ByteCode())
	if err != nil {
		t.Fatalf("running %s: %v", src, err)
	}
	return machine
}

func TestInterpolationJoinsTextAndHoles(t *testing.T) {
	cases := []struct{ src, want string }{
		{`let h = "db01"; "host=${h}";`, "host=db01"},
		{`let h = "db01"; let p = 5432; "${h}:${p}";`, "db01:5432"},
		{`"${ 2 + 3 * 4 }";`, "14"},
		{`let n = 7; "${n}";`, "7"},
		{`let ok = true; "ok=${ok}";`, "ok=true"},
		{`let xs = [1, 2]; "${xs}";`, "[1, 2]"},
		{`let f = fn(x) { return x * 2; }; "${ f(21) }";`, "42"},
		{`let h = {"k": "v"}; "${ h["k"] }";`, "v"},
		{`let a = "x"; "${ "${a}" }";`, "x"}, // a template inside a hole
	}
	for _, tc := range cases {
		assertStringResult(t, runOneFile(t, tc.src), tc.want)
	}
}

// TestAHoleProducesAStringEvenAlone pins the reason a single-piece template
// still goes through OpConcat: "${n}" has to be a string, not the integer n.
func TestAHoleProducesAStringEvenAlone(t *testing.T) {
	assertStringResult(t, runOneFile(t, `let n = 7; "${n}";`), "7")
}

func TestEscapedHoleIsLiteralText(t *testing.T) {
	assertStringResult(t, runOneFile(t, `"\${not a hole}";`), "${not a hole}")
	assertStringResult(t, runOneFile(t, `"cost: $5";`), "cost: $5")
}

func TestRawStringIsNotInterpolated(t *testing.T) {
	assertStringResult(t, runOneFile(t, `let x = 1; r"${x}";`), "${x}")
}

func TestRawStringKeepsItsBackslashes(t *testing.T) {
	assertStringResult(t, runOneFile(t, `r"C:\Users\Public";`), `C:\Users\Public`)
}

func TestTripleQuotedRunsAsWritten(t *testing.T) {
	src := "let who = \"analyst\";\n\"\"\"\n  hello ${who}\n  bye\n  \"\"\";"
	assertStringResult(t, runOneFile(t, src), "hello analyst\nbye")
}

// TestInterpolationIsNotFormatting pins that the text is text: a percent sign
// in an interpolated string is a percent sign, because no format string is
// built and nothing rescans the result.
func TestInterpolationIsNotFormatting(t *testing.T) {
	assertStringResult(t, runOneFile(t, `let n = 5; "${n}% done";`), "5% done")
}

// TestAShadowedBuiltinDoesNotChangeInterpolation is the reason concatenation is
// an opcode. If interpolation compiled to a call, a program that binds that
// name would quietly change what every interpolated string in it means.
func TestAShadowedBuiltinDoesNotChangeInterpolation(t *testing.T) {
	src := `let str_format = fn(a, b) { return "hijacked"; }; let n = 1; "n=${n}";`
	assertStringResult(t, runOneFile(t, src), "n=1")
}
