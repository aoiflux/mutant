package parser

import (
	"strings"
	"testing"

	"mutant/ast"
	"mutant/lexer"
)

func parseOne(t *testing.T, src string) (*ast.Program, *Parser) {
	t.Helper()
	p := New(lexer.New(src))
	return p.ParseProgram(), p
}

func firstTemplate(t *testing.T, src string) *ast.TemplateLiteral {
	t.Helper()
	program, p := parseOne(t, src)
	if errs := p.Errors(); len(errs) > 0 {
		t.Fatalf("parsing %s: %v", src, errs)
	}
	stmt, ok := program.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("first statement is %T, want an expression statement", program.Statements[0])
	}
	lit, ok := stmt.Expression.(*ast.TemplateLiteral)
	if !ok {
		t.Fatalf("expression is %T, want a template literal", stmt.Expression)
	}
	return lit
}

func TestTemplateHoleIsAParsedExpression(t *testing.T) {
	lit := firstTemplate(t, `"n=${ 1 + 2 }";`)

	// The text is data on the node and the holes are expressions, so a
	// literal with one hole has one part and two text slots around it.
	if len(lit.Parts) != 1 {
		t.Fatalf("got %d parts, want 1", len(lit.Parts))
	}
	if len(lit.Texts) != 2 {
		t.Fatalf("got %d text slots, want 2", len(lit.Texts))
	}
	if lit.Texts[0] != "n=" || lit.Texts[1] != "" {
		t.Fatalf("text slots are %q, want [n= ]", lit.Texts)
	}
	if _, ok := lit.Parts[0].(*ast.InfixExpression); !ok {
		t.Fatalf("the hole is %T, want an infix expression", lit.Parts[0])
	}
}

// TestHolePositionsAreFilePositions is the point of parsing each hole inside
// padding: a range recorded for a node in a hole has to be usable by an editor
// against this file, not against a fragment starting at line 1 column 1.
func TestHolePositionsAreFilePositions(t *testing.T) {
	src := "let a = 1;\nlet s = \"n=${a}\";"
	program, p := parseOne(t, src)
	if errs := p.Errors(); len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	let, ok := program.Statements[1].(*ast.LetStatement)
	if !ok {
		t.Fatalf("second statement is %T", program.Statements[1])
	}
	lit := let.Value.(*ast.TemplateLiteral)

	var hole *ast.Identifier
	for _, part := range lit.Parts {
		if ident, isIdent := part.(*ast.Identifier); isIdent {
			hole = ident
		}
	}
	if hole == nil {
		t.Fatal("no identifier part")
	}

	rng, ok := program.RangeOf(hole)
	if !ok {
		t.Fatal("no range recorded for the hole's identifier")
	}
	// `let s = "n=${a}";` -- the a is on line 2 at column 14.
	if rng.Start.Line != 2 || rng.Start.Column != 14 {
		t.Errorf("hole at %d:%d, want 2:14", rng.Start.Line, rng.Start.Column)
	}
	if want := strings.Index(src, "${a}") + 2; rng.Start.Offset != want {
		t.Errorf("hole offset %d, want %d", rng.Start.Offset, want)
	}
}

func TestHoleErrorsNameTheHole(t *testing.T) {
	cases := []struct{ src, want string }{
		{`"${}";`, "empty ${}"},
		{`"${ let x = 1; }";`, "has to be an expression"},
		{`"${ 1 2 }";`, "more than one expression"},
	}
	for _, tc := range cases {
		_, p := parseOne(t, tc.src)
		joined := strings.Join(p.Errors(), "\n")
		if !strings.Contains(joined, tc.want) {
			t.Errorf("%s reported %q, want something containing %q", tc.src, joined, tc.want)
		}
	}
}

// TestABrokenHoleReportsItsOwnLine keeps the padding honest: the error has to
// name the line the hole is on, not the line the string starts on.
func TestABrokenHoleReportsItsOwnLine(t *testing.T) {
	src := "let x = 1;\nlet y = 2;\nlet s = \"${ x + }\";"
	_, p := parseOne(t, src)
	joined := strings.Join(p.Errors(), "\n")
	if joined == "" {
		t.Fatal("a hole with a dangling operator parsed clean")
	}
	if !strings.Contains(joined, "3") {
		t.Errorf("errors %q do not mention line 3", joined)
	}
}

func TestImportPathCannotInterpolate(t *testing.T) {
	// Modules are resolved before the program runs, so a path that depends on
	// a value has nothing to be resolved against.
	_, p := parseOne(t, `import "lib/${name}.mut";`)
	joined := strings.Join(p.Errors(), "\n")
	if !strings.Contains(joined, "import path") {
		t.Errorf("errors %q do not refuse the interpolated path", joined)
	}
}
