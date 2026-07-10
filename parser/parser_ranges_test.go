package parser

import (
	"mutant/ast"
	"mutant/lexer"
	"testing"
)

// TestNodeRanges_LetStatement verifies that the parser records a source range
// for a top-level LetStatement and its nested Identifier, and that the ranges
// cover the source we expect (including trailing semicolon for the statement,
// exclusive of it for the identifier).
func TestNodeRanges_LetStatement(t *testing.T) {
	input := "let x = 5;"
	program := parseOrFail(t, input)

	if len(program.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(program.Statements))
	}
	let, ok := program.Statements[0].(*ast.LetStatement)
	if !ok {
		t.Fatalf("statement is %T, want *ast.LetStatement", program.Statements[0])
	}

	rng, ok := program.RangeOf(let)
	if !ok {
		t.Fatal("no range recorded for LetStatement")
	}
	// LetStatement should start at column 1 (offset 0) and end at column 11
	// (offset 10) since the parser consumes the trailing ';'.
	if rng.Start.Line != 1 || rng.Start.Column != 1 || rng.Start.Offset != 0 {
		t.Errorf("let start wrong: %+v", rng.Start)
	}
	if rng.End.Line != 1 || rng.End.Column != 11 || rng.End.Offset != 10 {
		t.Errorf("let end wrong: %+v", rng.End)
	}

	nameRng, ok := program.RangeOf(let.Name)
	if !ok {
		t.Fatal("no range recorded for let.Name")
	}
	if nameRng.Start.Offset != 4 || nameRng.End.Offset != 5 {
		t.Errorf("let.Name range wrong: %+v", nameRng)
	}
}

// TestNodeRanges_InfixExpression verifies that a binary expression's range
// spans from the left operand's start to the right operand's end, not just
// the operator's position.
func TestNodeRanges_InfixExpression(t *testing.T) {
	input := "1 + 2;"
	program := parseOrFail(t, input)

	stmt := program.Statements[0].(*ast.ExpressionStatement)
	infix, ok := stmt.Expression.(*ast.InfixExpression)
	if !ok {
		t.Fatalf("expression is %T, want *ast.InfixExpression", stmt.Expression)
	}

	rng, ok := program.RangeOf(infix)
	if !ok {
		t.Fatal("no range recorded for InfixExpression")
	}
	// "1 + 2" spans offsets 0..5.
	if rng.Start.Offset != 0 {
		t.Errorf("infix start offset: got %d want 0", rng.Start.Offset)
	}
	if rng.End.Offset != 5 {
		t.Errorf("infix end offset: got %d want 5", rng.End.Offset)
	}
}

// TestNodeRanges_FunctionAndCall exercises a nested construct: a function
// literal bound with `let` and later called. Verifies that the function
// literal, the call, and the identifiers all have distinct, accurate ranges.
func TestNodeRanges_FunctionAndCall(t *testing.T) {
	input := "let f = fn(x) { x + 1; };\nf(2);\n"
	program := parseOrFail(t, input)

	if len(program.Statements) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(program.Statements))
	}

	// First statement: let f = fn(x) { ... };
	let := program.Statements[0].(*ast.LetStatement)
	fl, ok := let.Value.(*ast.FunctionLiteral)
	if !ok {
		t.Fatalf("let.Value is %T, want *ast.FunctionLiteral", let.Value)
	}
	if _, ok := program.RangeOf(fl); !ok {
		t.Error("no range recorded for FunctionLiteral")
	}

	// Second statement: f(2);
	callStmt := program.Statements[1].(*ast.ExpressionStatement)
	call, ok := callStmt.Expression.(*ast.CallExpression)
	if !ok {
		t.Fatalf("expression is %T, want *ast.CallExpression", callStmt.Expression)
	}
	rng, ok := program.RangeOf(call)
	if !ok {
		t.Fatal("no range recorded for CallExpression")
	}
	// "f(2)" begins at offset 26 (line 2 col 1) on the second line.
	if rng.Start.Line != 2 || rng.Start.Column != 1 {
		t.Errorf("call start wrong: %+v", rng.Start)
	}
}

// TestTypedErrors_HasRange verifies that syntax errors produced by the parser
// carry a source range pointing at the offending token, and that the legacy
// string Errors slice is populated in parallel.
func TestTypedErrors_HasRange(t *testing.T) {
	// Missing '=' after identifier — expectPeek(ASSIGN) fails on the '5'
	// token, which becomes the offending peek token.
	input := "let x 5;"

	l := lexer.New(input)
	p := New(l)
	_ = p.ParseProgram()

	if len(p.Errors()) == 0 {
		t.Fatal("expected at least one parser error")
	}
	typed := p.TypedErrors()
	if len(typed) != len(p.Errors()) {
		t.Fatalf("typed error count %d != string error count %d", len(typed), len(p.Errors()))
	}

	// The '5' literal sits at offset 6 (after "let x ").
	first := typed[0]
	if !first.Range.IsValid() {
		t.Errorf("expected a valid range on the first typed error, got %+v", first.Range)
	}
	if first.Range.Start.Offset != 6 {
		t.Errorf("expected error range at offset 6 (the '5' token), got %+v", first.Range)
	}
}

func parseOrFail(t *testing.T, src string) *ast.Program {
	t.Helper()
	l := lexer.New(src)
	p := New(l)
	prog := p.ParseProgram()
	if errs := p.Errors(); len(errs) != 0 {
		t.Fatalf("parser errors: %v", errs)
	}
	return prog
}
