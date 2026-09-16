package parser

import (
	"strings"
	"testing"

	"mutant/ast"
	"mutant/lexer"
)

func firstMatch(t *testing.T, src string) *ast.MatchExpression {
	t.Helper()
	p := New(lexer.New(src))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		t.Fatalf("parsing %s: %v", src, errs)
	}
	stmt, ok := program.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("first statement is %T, want an expression statement", program.Statements[0])
	}
	exp, ok := stmt.Expression.(*ast.MatchExpression)
	if !ok {
		t.Fatalf("expression is %T, want a match expression", stmt.Expression)
	}
	return exp
}

func matchErrors(t *testing.T, src string) []string {
	t.Helper()
	p := New(lexer.New(src))
	p.ParseProgram()
	return p.Errors()
}

func TestMatchParsesSubjectAndArms(t *testing.T) {
	exp := firstMatch(t, `match (n) { 1 => "one", 2 => "two", _ => "many" }`)

	if exp.Subject == nil {
		t.Fatal("no subject parsed")
	}
	if len(exp.Arms) != 3 {
		t.Fatalf("parsed %d arms, want 3", len(exp.Arms))
	}
	if exp.Arms[2].IsWildcard() != true {
		t.Error("the `_` arm did not report itself as the wildcard")
	}
	for i, arm := range exp.Arms[:2] {
		if len(arm.Patterns) != 1 {
			t.Errorf("arm %d has %d patterns, want 1", i, len(arm.Patterns))
		}
	}
}

// TestMatchIsAnExpression is why `match` is registered as a prefix parse
// function rather than as a case in parseStatement: a statement-only `match`
// would make this line unreachable.
func TestMatchIsAnExpression(t *testing.T) {
	p := New(lexer.New(`let label = match (n) { 1 => "one", _ => "many" };`))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		t.Fatalf("a match on the right of a let did not parse: %v", errs)
	}
	let, ok := program.Statements[0].(*ast.LetStatement)
	if !ok {
		t.Fatalf("first statement is %T, want a let", program.Statements[0])
	}
	if _, ok := let.Value.(*ast.MatchExpression); !ok {
		t.Fatalf("let bound a %T, want a match expression", let.Value)
	}
}

// TestMatchAlternativesAreNotBitwiseOr is the decision the pattern grammar
// exists for. `|` is the bitwise-or operator at SUM precedence, so an arm
// parsed with parseExpression would read `1 | 2 | 3` as the number 3 and match
// one value nobody wrote.
func TestMatchAlternativesAreNotBitwiseOr(t *testing.T) {
	exp := firstMatch(t, `match (n) { 1 | 2 | 3 => "few", _ => "many" }`)
	if got := len(exp.Arms[0].Patterns); got != 3 {
		t.Fatalf("the first arm has %d patterns, want 3 -- `|` was read as an operator", got)
	}
	for i, want := range []string{"1", "2", "3"} {
		if got := exp.Arms[0].Patterns[i].String(); got != want {
			t.Errorf("alternative %d is %q, want %q", i, got, want)
		}
	}
}

// TestMatchWildcardIsNotANamedIdentifier pins the representation every walker
// depends on: no patterns at all, never an Identifier called "_". An identifier
// would have to be special-cased by every name-resolving walker, and the one
// that forgot would report it undefined.
func TestMatchWildcardIsNotANamedIdentifier(t *testing.T) {
	exp := firstMatch(t, `match (n) { _ => 0 }`)
	arm := exp.Arms[0]
	if !arm.IsWildcard() {
		t.Fatal("`_` did not parse as the wildcard")
	}
	if len(arm.Patterns) != 0 {
		t.Fatalf("the wildcard carries %d patterns, want none", len(arm.Patterns))
	}
}

func TestMatchArmBodyIsAlwaysABlock(t *testing.T) {
	// Braced and bare bodies are stored the same way so every walker has one
	// shape to walk; Braced records which was written, for the formatter.
	exp := firstMatch(t, `match (n) { 1 => "one", 2 => { "two" } }`)

	bare := exp.Arms[0]
	if bare.Body == nil || len(bare.Body.Statements) != 1 {
		t.Fatalf("a bare body did not become a one-statement block: %v", bare.Body)
	}
	if bare.Braced {
		t.Error("a bare body reported itself as braced")
	}
	if !exp.Arms[1].Braced {
		t.Error("a braced body did not report itself as braced")
	}
}

func TestMatchParsesEnumVariantPatterns(t *testing.T) {
	exp := firstMatch(t, `match (s) { Status.Ok => 1, mod.Status.Failed => 2, _ => 3 }`)

	first, ok := exp.Arms[0].Patterns[0].(*ast.FieldExpression)
	if !ok {
		t.Fatalf("`Status.Ok` parsed as %T, want a field expression", exp.Arms[0].Patterns[0])
	}
	if got := first.String(); got != "(Status.Ok)" {
		t.Errorf("`Status.Ok` printed as %q", got)
	}
	if got := exp.Arms[1].Patterns[0].String(); got != "((mod.Status).Failed)" {
		t.Errorf("a module-qualified variant printed as %q", got)
	}
}

func TestMatchParsesNegativeNumberPatterns(t *testing.T) {
	exp := firstMatch(t, `match (n) { -1 => "neg", -1.5 => "negf", _ => "other" }`)
	for i, want := range []string{"(-1)", "(-1.5)"} {
		if got := exp.Arms[i].Patterns[0].String(); got != want {
			t.Errorf("arm %d pattern is %q, want %q", i, got, want)
		}
	}
}

func TestMatchAcceptsATrailingComma(t *testing.T) {
	exp := firstMatch(t, `match (n) { 1 => "one", _ => "many", }`)
	if len(exp.Arms) != 2 {
		t.Fatalf("parsed %d arms, want 2", len(exp.Arms))
	}
}

func TestMatchNeedsNoSemicolon(t *testing.T) {
	// A match standing alone as a statement ends with its closing brace, the
	// way an `if` does. The formatter emits terminators from this answer, so a
	// wrong answer rewrites the file rather than reporting anything.
	src := `match (n) { 1 => putln("one"), _ => putln("many") }`
	p := New(lexer.New(src))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		t.Fatalf("a match statement without a `;` did not parse: %v", errs)
	}
	stmt, ok := program.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("first statement is %T", program.Statements[0])
	}
	if stmt.RequiresSemicolon() {
		t.Error("a match statement asked for a terminator")
	}
}

func TestMatchRejectsBadSource(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		mention string
	}{
		// Without the parens `{` is an infix at CALL precedence, so this would
		// otherwise parse clean as a struct literal named `n` and swallow the
		// arms. Same hazard `while` documents.
		{"no parens around the subject", `match n { 1 => 2 }`, "("},
		{"a bare name as a pattern", `match (n) { total => 1 }`, "is a name, not a pattern"},
		{"an interpolated string as a pattern", "match (n) { \"${x}\" => 1 }", "interpolated string is not a pattern"},
		{"no arms", `match (n) { }`, "at least one arm"},
		{"a missing comma", `match (n) { 1 => 2 3 => 4 }`, "separated by `,`"},
		{"an unclosed brace", `match (n) { 1 => 2`, "no closing"},
		{"`-` without a number", `match (n) { -x => 1 }`, "must be followed by a number"},
		{"a pattern that is not one", `match (n) { [1] => 2 }`, "expected a pattern"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := matchErrors(t, tt.src)
			if len(errs) == 0 {
				t.Fatalf("%q parsed without complaint", tt.src)
			}
			if !strings.Contains(strings.Join(errs, "\n"), tt.mention) {
				t.Errorf("errors %v do not mention %q", errs, tt.mention)
			}
		})
	}
}

func TestMatchPrintsBackAsMatch(t *testing.T) {
	exp := firstMatch(t, `match (n) { 1 => "one", _ => "many" }`)
	if got := exp.String(); !strings.HasPrefix(got, "match (") {
		t.Errorf("printed as %q, want it to start with `match (`", got)
	}
}
