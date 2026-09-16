package parser

import (
	"strings"
	"testing"

	"mutant/ast"
	"mutant/lexer"
)

func firstWhile(t *testing.T, src string) *ast.WhileStatement {
	t.Helper()
	p := New(lexer.New(src))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		t.Fatalf("parsing %s: %v", src, errs)
	}
	stmt, ok := program.Statements[0].(*ast.WhileStatement)
	if !ok {
		t.Fatalf("first statement is %T, want a while statement", program.Statements[0])
	}
	return stmt
}

func TestWhileParsesConditionAndBody(t *testing.T) {
	stmt := firstWhile(t, "while (i < 10) { i = i + 1; }")

	if stmt.Condition == nil {
		t.Fatal("no condition parsed")
	}
	if _, ok := stmt.Condition.(*ast.InfixExpression); !ok {
		t.Fatalf("condition is %T, want an infix expression", stmt.Condition)
	}
	if stmt.Body == nil || len(stmt.Body.Statements) != 1 {
		t.Fatalf("body has %v statements, want 1", stmt.Body)
	}
}

func TestWhileBodyMayBeEmpty(t *testing.T) {
	stmt := firstWhile(t, "while (next()) { }")
	if stmt.Body == nil {
		t.Fatal("an empty body parsed as no body at all")
	}
	if len(stmt.Body.Statements) != 0 {
		t.Fatalf("empty body has %d statements", len(stmt.Body.Statements))
	}
}

// TestWhileIsNotSugarForFor is the decision this node exists for: the printed
// form has to be the form that was written. A shared ForStatement would print
// `for (; i < 10; )` here.
func TestWhileIsNotSugarForFor(t *testing.T) {
	stmt := firstWhile(t, "while (i < 10) { i = i + 1; }")
	if got := stmt.String(); !strings.HasPrefix(got, "while (") {
		t.Errorf("printed as %q, want it to start with `while (`", got)
	}
}

func TestWhileNeedsNoSemicolon(t *testing.T) {
	// `while` ends with its body's `}`, like `for`. A parser that demanded a
	// terminator would reject every well-formed loop.
	src := "while (a) { b(); }\nwhile (c) { d(); }\n"
	p := New(lexer.New(src))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		t.Fatalf("two adjacent loops did not parse: %v", errs)
	}
	if len(program.Statements) != 2 {
		t.Fatalf("got %d statements, want 2", len(program.Statements))
	}
}

func TestWhileErrors(t *testing.T) {
	cases := []struct{ src, want string }{
		{"while i < 10 { }", "("},
		{"while () { }", "needs a condition"},
		{"while (i < 10) i = i + 1;", "{"},
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

// TestEndlessWhileIsSpelledOut records decision 1's smaller half: `while ()` is
// refused rather than read as `while (true)`, so an endless loop has to say so.
func TestEndlessWhileIsSpelledOut(t *testing.T) {
	p := New(lexer.New("while () { }"))
	p.ParseProgram()
	joined := strings.Join(p.Errors(), "\n")
	if !strings.Contains(joined, "while (true)") {
		t.Errorf("the error %q does not name the spelling that works", joined)
	}
}

func TestWhileRecordsARange(t *testing.T) {
	src := "let i = 0;\nwhile (i < 2) { i = i + 1; }"
	p := New(lexer.New(src))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	stmt := program.Statements[1].(*ast.WhileStatement)
	rng, ok := program.RangeOf(stmt)
	if !ok {
		t.Fatal("no range recorded for the while statement")
	}
	if rng.Start.Line != 2 || rng.Start.Column != 1 {
		t.Errorf("range starts at %d:%d, want 2:1", rng.Start.Line, rng.Start.Column)
	}
}
