package parser

import (
	"mutant/ast"
	"mutant/lexer"
	"testing"
)

func parseSource(t *testing.T, input string) (*ast.Program, *Parser) {
	t.Helper()
	p := New(lexer.New(input))
	program := p.ParseProgram()
	return program, p
}

// requireNoHardErrors asserts the parser produced a usable tree. Recoverable
// problems (missing/extra semicolons) must never surface here — keeping them
// out of Errors is what lets the CLI, compiler and evaluator stay unchanged
// while the formatter still gets to see and repair them.
func requireNoHardErrors(t *testing.T, p *Parser) {
	t.Helper()
	if errs := p.Errors(); len(errs) != 0 {
		t.Fatalf("expected no hard parse errors, got %v", errs)
	}
}

func TestRequiresSemicolonByStatementKind(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"let", "let x = 5;", true},
		{"return", "fn() { return 5; };", true},
		{"expression", "foobar;", true},
		{"call expression", "add(1, 2);", true},
		{"function literal expression", "fn(x) { x; };", true},
		{"if expression statement", "if (x) { y; }", false},
		{"if else expression statement", "if (x) { y; } else { z; }", false},
		{"for", "for (let i = 0; i < 3; i = i + 1) { i; }", false},
		{"struct", "struct Point { x; y; }", false},
		{"enum", "enum Color { Red, Green }", false},
		{"break", "for (;;) { break; }", true},
		{"continue", "for (;;) { continue; }", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program, p := parseSource(t, tt.input)
			requireNoHardErrors(t, p)

			stmt := targetStatement(t, tt.name, program)
			if got := stmt.RequiresSemicolon(); got != tt.want {
				t.Errorf("%T.RequiresSemicolon() = %v, want %v", stmt, got, tt.want)
			}
		})
	}
}

// targetStatement digs out the statement each RequiresSemicolon case is about.
// Most inputs are a single top-level statement; `return`, `break` and
// `continue` are only legal nested, so they are unwrapped here.
func targetStatement(t *testing.T, name string, program *ast.Program) ast.Statement {
	t.Helper()
	if len(program.Statements) == 0 {
		t.Fatalf("%s: program has no statements", name)
	}
	outer := program.Statements[0]

	switch name {
	case "return":
		expStmt, ok := outer.(*ast.ExpressionStatement)
		if !ok {
			t.Fatalf("%s: outer statement is %T, want *ast.ExpressionStatement", name, outer)
		}
		fn, ok := expStmt.Expression.(*ast.FunctionLiteral)
		if !ok {
			t.Fatalf("%s: expression is %T, want *ast.FunctionLiteral", name, expStmt.Expression)
		}
		return fn.Body.Statements[0]
	case "break", "continue":
		forStmt, ok := outer.(*ast.ForStatement)
		if !ok {
			t.Fatalf("%s: outer statement is %T, want *ast.ForStatement", name, outer)
		}
		return forStmt.Body.Statements[0]
	default:
		return outer
	}
}

func TestMissingSemicolonIsRecoverable(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"let", "let x = 5"},
		{"expression", "foobar"},
		{"return", "fn() { return 5 };"},
		{"break", "for (;;) { break }"},
		{"continue", "for (;;) { continue }"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, p := parseSource(t, tt.input)
			requireNoHardErrors(t, p)

			rec := p.Recoverables()
			if len(rec) != 1 {
				t.Fatalf("expected 1 recoverable error, got %d: %#v", len(rec), rec)
			}
			if rec[0].Kind != MissingSemicolon {
				t.Errorf("kind = %q, want %q", rec[0].Kind, MissingSemicolon)
			}
			// The range must be a zero-width insertion point so a quick fix
			// can splice in ";" without deleting anything.
			if rec[0].Range.Start != rec[0].Range.End {
				t.Errorf("range = %+v, want zero-width", rec[0].Range)
			}
			if !rec[0].Range.IsValid() {
				t.Errorf("range %+v is not valid", rec[0].Range)
			}
		})
	}
}

func TestMissingSemicolonInsertionPointIsAfterFinalToken(t *testing.T) {
	input := "let x = 5"
	_, p := parseSource(t, input)

	rec := p.Recoverables()
	if len(rec) != 1 {
		t.Fatalf("expected 1 recoverable error, got %#v", rec)
	}

	// Offset 9 == len("let x = 5"), i.e. immediately past the `5`.
	if got := rec[0].Range.Start.Offset; got != len(input) {
		t.Errorf("insertion offset = %d, want %d", got, len(input))
	}

	repaired := input[:rec[0].Range.Start.Offset] + ";" + input[rec[0].Range.Start.Offset:]
	if repaired != "let x = 5;" {
		t.Errorf("applying the fix produced %q, want %q", repaired, "let x = 5;")
	}

	// And the repaired source must parse cleanly.
	_, fixed := parseSource(t, repaired)
	requireNoHardErrors(t, fixed)
	if r := fixed.Recoverables(); len(r) != 0 {
		t.Errorf("repaired source still has recoverables: %#v", r)
	}
}

// A missing semicolon used to make parseLetStatement consume the first token
// of the *next* statement, silently corrupting everything after it.
func TestMissingSemicolonDoesNotSwallowNextStatement(t *testing.T) {
	program, p := parseSource(t, "let x = 5\nlet y = 6;\n")
	requireNoHardErrors(t, p)

	if len(program.Statements) != 2 {
		t.Fatalf("expected 2 statements, got %d: %s", len(program.Statements), program.String())
	}

	for i, wantName := range []string{"x", "y"} {
		letStmt, ok := program.Statements[i].(*ast.LetStatement)
		if !ok {
			t.Fatalf("statement %d is %T, want *ast.LetStatement", i, program.Statements[i])
		}
		if letStmt.Name.Value != wantName {
			t.Errorf("statement %d name = %q, want %q", i, letStmt.Name.Value, wantName)
		}
	}

	if rec := p.Recoverables(); len(rec) != 1 || rec[0].Kind != MissingSemicolon {
		t.Errorf("expected exactly one missing-semicolon recoverable, got %#v", rec)
	}
}

func TestRedundantSemicolonIsRecoverable(t *testing.T) {
	program, p := parseSource(t, "let x = 5;;\n")
	requireNoHardErrors(t, p)

	// The stray `;` must not become a statement, so the formatter drops it
	// simply by not re-emitting it.
	if len(program.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d: %s", len(program.Statements), program.String())
	}

	rec := p.Recoverables()
	if len(rec) != 1 {
		t.Fatalf("expected 1 recoverable error, got %d: %#v", len(rec), rec)
	}
	if rec[0].Kind != RedundantSemicolon {
		t.Errorf("kind = %q, want %q", rec[0].Kind, RedundantSemicolon)
	}
	// The range must cover the stray token so it can be deleted verbatim.
	if got := rec[0].Range.End.Offset - rec[0].Range.Start.Offset; got != 1 {
		t.Errorf("range width = %d, want 1", got)
	}
	if rec[0].Range.Start.Offset != 10 {
		t.Errorf("range start offset = %d, want 10", rec[0].Range.Start.Offset)
	}
}

func TestRedundantSemicolonInsideBlock(t *testing.T) {
	program, p := parseSource(t, "fn() { let x = 5;;; };")
	requireNoHardErrors(t, p)

	rec := p.Recoverables()
	if len(rec) != 2 {
		t.Fatalf("expected 2 recoverable errors, got %d: %#v", len(rec), rec)
	}
	for i, r := range rec {
		if r.Kind != RedundantSemicolon {
			t.Errorf("recoverable %d kind = %q, want %q", i, r.Kind, RedundantSemicolon)
		}
	}

	expStmt := program.Statements[0].(*ast.ExpressionStatement)
	fn := expStmt.Expression.(*ast.FunctionLiteral)
	if len(fn.Body.Statements) != 1 {
		t.Errorf("block has %d statements, want 1 (stray semicolons dropped)", len(fn.Body.Statements))
	}
}

func TestWellFormedSourceHasNoRecoverables(t *testing.T) {
	input := `let x = 5;
let add = fn(a, b) { return a + b; };
struct Point { x; y; }
enum Color { Red, Green }
for (let i = 0; i < 3; i = i + 1) {
    if (i > 1) { break; } else { continue; }
}
add(1, 2);
`
	_, p := parseSource(t, input)
	requireNoHardErrors(t, p)

	if rec := p.Recoverables(); len(rec) != 0 {
		t.Errorf("expected no recoverables, got %#v", rec)
	}
}

func TestProgramPublishesComments(t *testing.T) {
	input := "// leading\nlet x = 5; // trailing\n"

	program, p := parseSource(t, input)
	requireNoHardErrors(t, p)

	if len(program.Comments) != 2 {
		t.Fatalf("expected 2 comments on the program, got %d: %#v", len(program.Comments), program.Comments)
	}
	if program.Comments[0].Text != "// leading" {
		t.Errorf("comment 0 = %q, want %q", program.Comments[0].Text, "// leading")
	}
	if program.Comments[1].Text != "// trailing" {
		t.Errorf("comment 1 = %q, want %q", program.Comments[1].Text, "// trailing")
	}
}

func TestCommentsDoNotTriggerRecoverables(t *testing.T) {
	input := `// a comment
let x = 5; // trailing comment
// another
let y = 6;
`
	_, p := parseSource(t, input)
	requireNoHardErrors(t, p)

	if rec := p.Recoverables(); len(rec) != 0 {
		t.Errorf("comments should not produce recoverables, got %#v", rec)
	}
}
