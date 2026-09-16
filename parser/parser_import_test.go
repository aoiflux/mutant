package parser

import (
	"strings"
	"testing"

	"mutant/ast"
	"mutant/lexer"
)

func parseImportSource(t *testing.T, input string) (*ast.Program, *Parser) {
	t.Helper()
	p := New(lexer.New(input))
	return p.ParseProgram(), p
}

func TestImportStatementParsing(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		alias     string
		path      string
		namespace string
	}{
		{
			name:      "unaliased import derives its namespace from the file name",
			input:     `import "pkg/util.mut";`,
			alias:     "",
			path:      "pkg/util.mut",
			namespace: "util",
		},
		{
			name:      "aliased import binds the alias",
			input:     `import strings "pkg/util.mut";`,
			alias:     "strings",
			path:      "pkg/util.mut",
			namespace: "strings",
		},
		{
			name:      "a bare file name still yields a namespace",
			input:     `import "util.mut";`,
			alias:     "",
			path:      "util.mut",
			namespace: "util",
		},
		{
			name:      "a windows-style separator resolves the same base name",
			input:     `import "pkg\\util.mut";`,
			alias:     "",
			path:      `pkg\util.mut`,
			namespace: "util",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program, p := parseImportSource(t, tt.input)
			checkParserErrors(t, p)

			if len(program.Statements) != 1 {
				t.Fatalf("expected 1 statement, got=%d", len(program.Statements))
			}

			stmt, ok := program.Statements[0].(*ast.ImportStatement)
			if !ok {
				t.Fatalf("program.Statements[0] is not *ast.ImportStatement. got=%T", program.Statements[0])
			}

			if tt.alias == "" {
				if stmt.Alias != nil {
					t.Fatalf("expected no alias, got=%q", stmt.Alias.Value)
				}
			} else {
				if stmt.Alias == nil {
					t.Fatalf("expected alias %q, got none", tt.alias)
				}
				if stmt.Alias.Value != tt.alias {
					t.Fatalf("expected alias %q, got=%q", tt.alias, stmt.Alias.Value)
				}
			}

			if stmt.Path == nil {
				t.Fatalf("expected a path literal, got none")
			}
			if stmt.Path.Value != tt.path {
				t.Fatalf("expected path %q, got=%q", tt.path, stmt.Path.Value)
			}
			if got := stmt.Namespace(); got != tt.namespace {
				t.Fatalf("expected namespace %q, got=%q", tt.namespace, got)
			}
			if !stmt.RequiresSemicolon() {
				t.Fatalf("an import statement must require a terminator")
			}
		})
	}
}

// TestImportStatementRejectsNonStringPath pins the decision that an import
// path is a literal, not an expression. Resolution happens before anything
// runs, so a computed path could never be evaluated.
func TestImportStatementRejectsNonStringPath(t *testing.T) {
	for _, input := range []string{
		`import pkg;`,
		`import util pkg;`,
		`import 42;`,
		`import;`,
	} {
		t.Run(input, func(t *testing.T) {
			program, p := parseImportSource(t, input)
			if len(p.Errors()) == 0 {
				t.Fatalf("expected a parse error for %q, got none", input)
			}
			if !strings.Contains(p.Errors()[0], "import path as a quoted string") {
				t.Fatalf("unexpected error for %q: %s", input, p.Errors()[0])
			}
			for _, stmt := range program.Statements {
				if _, ok := stmt.(*ast.ImportStatement); ok {
					t.Fatalf("a rejected import must not reach the tree: %q", input)
				}
			}
		})
	}
}

// TestImportStatementIsTopLevelOnly pins the placement rule. Modules are
// linked into one program before it runs, so an import inside a block would be
// loaded whether or not control ever reached it.
func TestImportStatementIsTopLevelOnly(t *testing.T) {
	for _, input := range []string{
		`let f = fn() { import "pkg/util.mut"; };`,
		`for (; true; ) { import "pkg/util.mut"; }`,
		`if (true) { import "pkg/util.mut"; }`,
		`let f = fn() { let g = fn() { import "pkg/util.mut"; }; };`,
	} {
		t.Run(input, func(t *testing.T) {
			_, p := parseImportSource(t, input)
			errs := p.Errors()
			if len(errs) == 0 {
				t.Fatalf("expected a nested-import error for %q, got none", input)
			}
			if !strings.Contains(errs[0], "only allowed at the top level") {
				t.Fatalf("unexpected error for %q: %s", input, errs[0])
			}
		})
	}
}

// TestImportAfterBlockStaysTopLevel guards the depth counter itself: a block
// that opens and closes must leave the depth where it found it, or every
// import following a function declaration would be rejected.
func TestImportAfterBlockStaysTopLevel(t *testing.T) {
	input := `let f = fn() { return 1; };
import "pkg/util.mut";`

	program, p := parseImportSource(t, input)
	checkParserErrors(t, p)

	if len(program.Statements) != 2 {
		t.Fatalf("expected 2 statements, got=%d", len(program.Statements))
	}
	if _, ok := program.Statements[1].(*ast.ImportStatement); !ok {
		t.Fatalf("program.Statements[1] is not *ast.ImportStatement. got=%T", program.Statements[1])
	}
}

func TestImportStatementString(t *testing.T) {
	tests := []struct{ input, want string }{
		{`import "pkg/util.mut";`, `import "pkg/util.mut";`},
		{`import strings "pkg/util.mut";`, `import strings "pkg/util.mut";`},
	}

	for _, tt := range tests {
		program, p := parseImportSource(t, tt.input)
		checkParserErrors(t, p)
		if got := program.Statements[0].String(); got != tt.want {
			t.Fatalf("expected %q, got=%q", tt.want, got)
		}
	}
}
