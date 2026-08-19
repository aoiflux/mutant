package parser

import (
	"mutant/ast"
	"mutant/lexer"
	"testing"
)

func parseSingleExpression(t *testing.T, input string) *ast.AssignExpression {
	t.Helper()
	p := New(lexer.New(input))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) != 0 {
		t.Fatalf("parser errors for %q: %v", input, errs)
	}
	if len(program.Statements) != 1 {
		t.Fatalf("expected 1 statement for %q, got %d", input, len(program.Statements))
	}
	stmt, ok := program.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("statement is not *ast.ExpressionStatement, got %T", program.Statements[0])
	}
	assign, ok := stmt.Expression.(*ast.AssignExpression)
	if !ok {
		t.Fatalf("expression is not *ast.AssignExpression, got %T", stmt.Expression)
	}
	return assign
}

func TestParseCompoundAssignmentOperators(t *testing.T) {
	tests := []struct {
		input        string
		wantOperator string
	}{
		{"x += 1;", "+"},
		{"x -= 1;", "-"},
		{"x *= 2;", "*"},
		{"x /= 2;", "/"},
		{"x %= 2;", "%"},
	}

	for _, tt := range tests {
		assign := parseSingleExpression(t, tt.input)
		if assign.Operator != tt.wantOperator {
			t.Fatalf("%q: expected Operator %q, got %q", tt.input, tt.wantOperator, assign.Operator)
		}
		if assign.Postfix != "" {
			t.Fatalf("%q: expected empty Postfix, got %q", tt.input, assign.Postfix)
		}
		ident, ok := assign.Left.(*ast.Identifier)
		if !ok || ident.Value != "x" {
			t.Fatalf("%q: expected target identifier x, got %#v", tt.input, assign.Left)
		}
	}
}

func TestParsePostfixIncrementDecrement(t *testing.T) {
	tests := []struct {
		input        string
		wantOperator string
		wantPostfix  string
	}{
		{"x++;", "+", "++"},
		{"x--;", "-", "--"},
	}

	for _, tt := range tests {
		assign := parseSingleExpression(t, tt.input)
		if assign.Operator != tt.wantOperator {
			t.Fatalf("%q: expected Operator %q, got %q", tt.input, tt.wantOperator, assign.Operator)
		}
		if assign.Postfix != tt.wantPostfix {
			t.Fatalf("%q: expected Postfix %q, got %q", tt.input, tt.wantPostfix, assign.Postfix)
		}
		lit, ok := assign.Value.(*ast.IntegerLiteral)
		if !ok || lit.Value != 1 {
			t.Fatalf("%q: expected synthetic value 1, got %#v", tt.input, assign.Value)
		}
	}
}

// A compound assignment against a non-assignable target is a parse error.
func TestParseCompoundAssignmentInvalidTarget(t *testing.T) {
	p := New(lexer.New("1 += 2;"))
	p.ParseProgram()
	if len(p.Errors()) == 0 {
		t.Fatal("expected a parser error for compound assignment to a literal")
	}
}
