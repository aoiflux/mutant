package builtin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A builtin's name is declared once, in names.go, and the dispatch table and the
// metadata both say the constant rather than the string. The error messages the
// user actually reads used to say it a third way -- as a literal, inside the
// implementation -- so renaming a builtin left every message it raises quoting
// a name that no longer existed. Three tests already catch the rename itself
// (TestSignaturesParse and the two legacy-ordinal tests); none of them looks at
// what the message says.
//
// The check works on the AST rather than on text for the same reason policy/
// does: short builtin names collide with ordinary hash keys, so "sort" as a
// literal is only suspicious inside the function registered as sort.
func TestNoBuiltinSpellsItsOwnNameAsALiteral(t *testing.T) {
	dir := repoBuiltinDir(t)
	fset := token.NewFileSet()

	constValue := parseNameConstants(t, fset, filepath.Join(dir, "names.go"))
	owner := parseDispatchTable(t, fset, filepath.Join(dir, "builtin.go"), constValue)
	if len(owner) < 400 {
		t.Fatalf("read only %d builtins out of the dispatch table; the table's shape must have changed", len(owner))
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		// names.go is where the names live, and legacy_ordinals.go is a frozen
		// record of what v2.4.0 shipped rather than live code.
		if name == "names.go" || name == "legacy_ordinals.go" {
			continue
		}

		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			want, registered := owner[fn.Name.Name]
			if !registered {
				continue
			}

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(lit.Value)
				if err != nil || value != want.value {
					return true
				}
				t.Errorf("%s:%d: %s spells its own name as the literal %q; say %s instead, "+
					"so renaming the builtin renames what its errors say",
					name, fset.Position(lit.Pos()).Line, fn.Name.Name, value, want.constant)
				return true
			})
		}
	}
}

type registration struct {
	value    string
	constant string
}

func parseNameConstants(t *testing.T, fset *token.FileSet, path string) map[string]string {
	t.Helper()

	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	out := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || len(spec.Values) != 1 {
			return true
		}
		lit, ok := spec.Values[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if value, err := strconv.Unquote(lit.Value); err == nil {
			out[spec.Names[0].Name] = value
		}
		return true
	})
	return out
}

// parseDispatchTable reads `{BuiltinNameX, &BuiltIn{GoFunc}}` rows, so the
// mapping from Go function to builtin name is the registered one rather than a
// guess from the naming convention.
func parseDispatchTable(t *testing.T, fset *token.FileSet, path string, constValue map[string]string) map[string]registration {
	t.Helper()

	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	out := map[string]registration{}
	ast.Inspect(file, func(n ast.Node) bool {
		row, ok := n.(*ast.CompositeLit)
		if !ok || len(row.Elts) != 2 {
			return true
		}
		ident, ok := row.Elts[0].(*ast.Ident)
		if !ok {
			return true
		}
		value, known := constValue[ident.Name]
		if !known {
			return true
		}
		unary, ok := row.Elts[1].(*ast.UnaryExpr)
		if !ok {
			return true
		}
		wrapper, ok := unary.X.(*ast.CompositeLit)
		if !ok || len(wrapper.Elts) != 1 {
			return true
		}
		fn, ok := wrapper.Elts[0].(*ast.Ident)
		if !ok {
			return true
		}
		out[fn.Name] = registration{value: value, constant: ident.Name}
		return true
	})
	return out
}

// repoBuiltinDir is this package's own directory. Tests run with it as the
// working directory, so "." is the answer; it is a function rather than a
// literal so the reason is written down once.
func repoBuiltinDir(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("locating the package directory: %v", err)
	}
	return dir
}
