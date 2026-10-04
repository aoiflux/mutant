package parser

import (
	"testing"

	"mutant/ast"
	"mutant/lexer"
)

// TestTheParserRecordsTheBracketsTheAuthorWrote: the tree has no node for a
// pair of brackets, so the program's side table is the only record the
// formatter has of the ones written for clarity. It holds the bracketed
// expression itself -- not its parent, and not a node written without them.
func TestTheParserRecordsTheBracketsTheAuthorWrote(t *testing.T) {
	p := New(lexer.New("let x = (a + b) * c; let y = a + b; let z = ((d));"))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		t.Fatalf("fixture did not parse: %v", errs)
	}

	value := func(i int) ast.Expression {
		return program.Statements[i].(*ast.LetStatement).Value
	}
	x := value(0).(*ast.InfixExpression)
	if !program.IsParenthesized(x.Left) {
		t.Errorf("(a + b) in %q is not recorded as bracketed", x.String())
	}
	if program.IsParenthesized(x) || program.IsParenthesized(x.Right) {
		t.Errorf("%q: a node written without brackets is recorded as bracketed", x.String())
	}
	if program.IsParenthesized(value(1)) {
		t.Errorf("a + b, written without brackets, is recorded as bracketed")
	}
	if !program.IsParenthesized(value(2)) {
		t.Errorf("((d)) is not recorded as bracketed")
	}
	if n := len(program.Parenthesized); n != 2 {
		t.Errorf("recorded %d bracketed expressions, want 2: (a + b) and d once", n)
	}
}

// TestAProgramWithNoBracketsHasNoSideTable keeps the common case free: a file
// without a bracketed expression allocates nothing for them.
func TestAProgramWithNoBracketsHasNoSideTable(t *testing.T) {
	program := New(lexer.New("let x = a + b * c;")).ParseProgram()
	if program.Parenthesized != nil {
		t.Errorf("Parenthesized = %v, want nil", program.Parenthesized)
	}
}
