package parser

import (
	"strings"
	"testing"

	"mutant/ast"
	"mutant/lexer"
)

func firstForIn(t *testing.T, src string) *ast.ForInStatement {
	t.Helper()
	p := New(lexer.New(src))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		t.Fatalf("parsing %s: %v", src, errs)
	}
	stmt, ok := program.Statements[0].(*ast.ForInStatement)
	if !ok {
		t.Fatalf("first statement is %T, want a for-in statement", program.Statements[0])
	}
	return stmt
}

func TestForInParsesOneBinding(t *testing.T) {
	stmt := firstForIn(t, "for (v in xs) { use(v); }")

	if stmt.Key != nil {
		t.Errorf("a one-binding loop parsed a key: %v", stmt.Key)
	}
	if stmt.Value == nil || stmt.Value.Value != "v" {
		t.Fatalf("value binding is %v, want v", stmt.Value)
	}
	if ident, ok := stmt.Iterable.(*ast.Identifier); !ok || ident.Value != "xs" {
		t.Fatalf("iterable is %v, want the identifier xs", stmt.Iterable)
	}
}

func TestForInParsesTwoBindings(t *testing.T) {
	stmt := firstForIn(t, "for (i, v in xs) { use(i, v); }")

	if stmt.Key == nil || stmt.Key.Value != "i" {
		t.Fatalf("key binding is %v, want i", stmt.Key)
	}
	if stmt.Value == nil || stmt.Value.Value != "v" {
		t.Fatalf("value binding is %v, want v", stmt.Value)
	}
}

// TestForInIterableMayBeAnyExpression keeps the header from being restricted to
// a name: `for (x in range(0, 10))` is the spelling decision 4 depends on.
func TestForInIterableMayBeAnyExpression(t *testing.T) {
	for _, src := range []string{
		"for (v in [1, 2, 3]) { }",
		"for (v in range(0, 10)) { }",
		`for (v in {"a": 1}) { }`,
		"for (v in h[\"k\"]) { }",
		"for (v in obj.field) { }",
		`for (c in "abc") { }`,
	} {
		stmt := firstForIn(t, src)
		if stmt.Iterable == nil {
			t.Errorf("%s parsed no iterable", src)
		}
	}
}

// TestClassicForStillParses is the half that could regress silently: the
// lookahead that recognises a for-in header must not swallow a C-style one.
func TestClassicForStillParses(t *testing.T) {
	for _, src := range []string{
		"for (let i = 0; i < 10; i = i + 1) { }",
		"for (;;) { }",
		"for (i = 0; i < 10; i = i + 1) { }",
		"for (; i < 10; ) { }",
		"for (let i = 0; i < 10; i++) { }",
	} {
		p := New(lexer.New(src))
		program := p.ParseProgram()
		if errs := p.Errors(); len(errs) > 0 {
			t.Errorf("%s did not parse: %v", src, errs)
			continue
		}
		if _, ok := program.Statements[0].(*ast.ForStatement); !ok {
			t.Errorf("%s parsed as %T, want a classic for statement", src, program.Statements[0])
		}
	}
}

func TestForInPrintsAsItWasWritten(t *testing.T) {
	cases := []struct{ src, want string }{
		{"for (v in xs) { }", "for (v in xs)"},
		{"for (i, v in xs) { }", "for (i, v in xs)"},
	}
	for _, tc := range cases {
		stmt := firstForIn(t, tc.src)
		if got := stmt.String(); !strings.HasPrefix(got, tc.want) {
			t.Errorf("%s printed as %q, want it to start %q", tc.src, got, tc.want)
		}
	}
}

func TestForInErrors(t *testing.T) {
	cases := []struct{ src, want string }{
		{"for (v in) { }", "iterate over"},
		{"for (i, in xs) { }", "IDENT"},
		{"for (v in xs { }", ")"},
		{"for (v in xs) use(v);", "{"},
	}
	for _, tc := range cases {
		p := New(lexer.New(tc.src))
		p.ParseProgram()
		joined := strings.Join(p.Errors(), "\n")
		if joined == "" {
			t.Errorf("%q parsed clean, want an error", tc.src)
			continue
		}
		if !strings.Contains(joined, tc.want) {
			t.Errorf("%q reported %q, want something containing %q", tc.src, joined, tc.want)
		}
	}
}

// TestInIsAKeywordOnlyInAForHeader is worth pinning because adding a keyword
// takes the word away from every program that used it as a name. `in` is short
// and plausible, so the cost is recorded here rather than discovered later.
func TestInIsNowAKeyword(t *testing.T) {
	p := New(lexer.New("let in = 1;"))
	p.ParseProgram()
	if len(p.Errors()) == 0 {
		t.Errorf("`in` is a keyword now, so it cannot also be a variable name")
	}
}

func TestForInRecordsRangesForItsBindings(t *testing.T) {
	src := "for (i, v in xs) { }"
	p := New(lexer.New(src))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	stmt := program.Statements[0].(*ast.ForInStatement)
	for _, binding := range []*ast.Identifier{stmt.Key, stmt.Value} {
		rng, ok := program.RangeOf(binding)
		if !ok {
			t.Fatalf("no range recorded for %s", binding.Value)
		}
		if rng.Start.Line != 1 {
			t.Errorf("%s recorded on line %d, want 1", binding.Value, rng.Start.Line)
		}
	}

	// `for (i, v in xs)` -- i is at column 6 and v at column 9.
	if rng, _ := program.RangeOf(stmt.Key); rng.Start.Column != 6 {
		t.Errorf("key at column %d, want 6", rng.Start.Column)
	}
	if rng, _ := program.RangeOf(stmt.Value); rng.Start.Column != 9 {
		t.Errorf("value at column %d, want 9", rng.Start.Column)
	}
}
