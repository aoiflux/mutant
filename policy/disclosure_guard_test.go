package policy

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// disclosurePolicyDoc is named in every failure message, so the reader learns
// the rule and not merely that they broke it.
const disclosurePolicyDoc = "docs/DISCLOSURE_POLICY.md"

// scanDisclosureSource returns every Inspect call and every non-constant
// format string in one parsed file.
//
// A format argument is constant when it is a string literal, a concatenation
// of constants, or a string constant declared in the file. The one other form
// allowed is the `format` parameter inside a local wrapper -- a closure
// declared `name := func(format string, args ...any) ...` -- and only when
// every call of that wrapper in the same function passes a constant, which is
// checked here too. That is the pattern record.go uses to close a file before
// returning an error, and it keeps the rule exact: the format is still a
// constant at every call site a reviewer reads.
func scanDisclosureSource(fset *token.FileSet, rel string, file *ast.File) []finding {
	var out []finding
	funcs := functionSpans(file)
	enclosing := func(pos token.Pos) string {
		for _, fn := range funcs {
			if pos >= fn.start && pos <= fn.end {
				return fn.name
			}
		}
		return ""
	}
	add := func(pos token.Pos, what string) {
		out = append(out, finding{rel, fset.Position(pos).Line, enclosing(pos), what})
	}

	consts := map[string]bool{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			for _, name := range spec.(*ast.ValueSpec).Names {
				consts[name.Name] = true
			}
		}
	}
	var constant func(ast.Expr) bool
	constant = func(expr ast.Expr) bool {
		switch e := expr.(type) {
		case *ast.BasicLit:
			return e.Kind == token.STRING
		case *ast.ParenExpr:
			return constant(e.X)
		case *ast.BinaryExpr:
			return e.Op == token.ADD && constant(e.X) && constant(e.Y)
		case *ast.Ident:
			return consts[e.Name]
		}
		return false
	}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		// The wrappers declared in this function, and the extent of each body.
		wrappers := map[string]*ast.FuncLit{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				return true
			}
			name, ok := assign.Lhs[0].(*ast.Ident)
			lit, isLit := assign.Rhs[0].(*ast.FuncLit)
			if ok && isLit && isFormatWrapper(lit) {
				wrappers[name.Name] = lit
			}
			return true
		})
		insideWrapper := func(pos token.Pos) bool {
			for _, lit := range wrappers {
				if pos >= lit.Body.Pos() && pos <= lit.Body.End() {
					return true
				}
			}
			return false
		}

		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := disclosureCallName(call.Fun)
			if strings.HasSuffix(name, ".Inspect") && len(call.Args) == 0 {
				add(call.Pos(), "calls Inspect, which renders a buffer as its whole contents")
				return true
			}
			index, formatted := DisclosureFormatFuncs[name]
			if _, wrapper := wrappers[name]; wrapper {
				index, formatted = 0, true
			}
			if !formatted || index >= len(call.Args) {
				return true
			}
			arg := call.Args[index]
			if constant(arg) {
				return true
			}
			if ident, ok := arg.(*ast.Ident); ok && ident.Name == "format" && insideWrapper(call.Pos()) {
				return true
			}
			add(call.Pos(), name+" with a format that is not a constant")
			return true
		})
	}
	return out
}

// isFormatWrapper reports whether a closure is shaped func(format string, args ...any).
func isFormatWrapper(lit *ast.FuncLit) bool {
	params := lit.Type.Params.List
	if len(params) != 2 || len(params[0].Names) != 1 || params[0].Names[0].Name != "format" {
		return false
	}
	if ident, ok := params[0].Type.(*ast.Ident); !ok || ident.Name != "string" {
		return false
	}
	_, variadic := params[1].Type.(*ast.Ellipsis)
	return variadic
}

// disclosureCallName renders a call's function as "pkg.Name", "recv.Name" or
// "Name".
func disclosureCallName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if x, ok := f.X.(*ast.Ident); ok {
			return x.Name + "." + f.Sel.Name
		}
		return "." + f.Sel.Name
	}
	return ""
}

// The policy. The files that handle classified plaintext never call Inspect
// and never format with a string that is not a constant.
func TestDisclosureCodeNeverRendersPlaintext(t *testing.T) {
	fset := token.NewFileSet()
	var findings []finding
	scanned := 0
	for _, rel := range DisclosureFiles {
		path := filepath.Join(repositoryRoot, filepath.FromSlash(rel))
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Errorf("policy.DisclosureFiles names %s, which cannot be parsed: %v", rel, err)
			continue
		}
		scanned++
		findings = append(findings, scanDisclosureSource(fset, rel, file)...)
	}
	if scanned == 0 {
		t.Fatalf("scanned none of the %d files in policy.DisclosureFiles -- the walk is looking in the wrong place",
			len(DisclosureFiles))
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].file != findings[j].file {
			return findings[i].file < findings[j].file
		}
		return findings[i].line < findings[j].line
	})
	for _, f := range findings {
		t.Errorf("%s: code that handles classified plaintext must not render it into text. See %s, section 10",
			f, disclosurePolicyDoc)
	}
	t.Logf("scanned %d files that handle classified plaintext; %d findings", scanned, len(findings))
}

// keyMaterialNames mark a file as one that holds the key material that opens a
// classified record, derives it, asks for a passphrase that protects it, or
// puts the Classified mark on plaintext: the case session's case key and
// class-tag key, the grant and record-key operations, the passphrase request
// and the hook that answers it, and the one function that marks a read.
//
// Carrying the mark is not among them. The evaluator, the VM and the storage
// layer copy Classified from one buffer to the next; that is the runtime half
// of the enforcement doing its job, and those files render values by design.
var keyMaterialNames = map[string]bool{
	"caseKey":              true,
	"classTagKey":          true,
	"IssueGrant":           true,
	"SealGrant":            true,
	"UnwrapRecordKey":      true,
	"openSegment":          true,
	"RequestPassphrase":    true,
	"SetPassphraseSource":  true,
	"recordClassification": true,
}

// M26-SEC-001. DisclosureFiles is a declaration, and a file left off it was
// never scanned: the case session that holds the case key and the class-tag
// key, and the file that caches case-key passphrases, were both missing, and
// nothing said so. Every file that names key material is now held to the list.
func TestEveryFileHoldingKeyMaterialIsGuarded(t *testing.T) {
	listed := map[string]bool{}
	for _, rel := range DisclosureFiles {
		listed[rel] = true
	}
	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	holders := map[string][]string{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		ast.Inspect(file, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok && keyMaterialNames[ident.Name] && !seen[ident.Name] {
				seen[ident.Name] = true
				holders[rel] = append(holders[rel], ident.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
	// A walk that found nothing would pass by finding nothing to require.
	for _, known := range []string{"builtin/disclose.go", "security/record_grant.go", "builtin/record_read.go"} {
		if holders[known] == nil {
			t.Fatalf("%s names none of the key-material identifiers -- the walk or the names are wrong", known)
		}
	}
	var missing []string
	for rel, names := range holders {
		if !listed[rel] {
			sort.Strings(names)
			missing = append(missing, fmt.Sprintf("%s (%s)", rel, strings.Join(names, ", ")))
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("%s handles key material and is not in policy.DisclosureFiles, so the plaintext guard never "+
			"reads it. Add it. See %s, section 10", m, disclosurePolicyDoc)
	}
}

// The scanner catches what it says it catches. A guard that passes because its
// walk never matched anything is indistinguishable from one that passes because
// the code is clean, so each rule is exercised against source that breaks it.
func TestTheDisclosureGuardCatchesEachViolation(t *testing.T) {
	const source = `package probe

import "fmt"

const note = "a constant"

func render(secret string, buffer interface{ Inspect() string }) {
	_ = buffer.Inspect()                     // an Inspect call
	_ = fmt.Sprintf(secret)                  // a format built at run time
	_ = fmt.Errorf("%s: " + secret)          // a concatenation with a variable in it
	_ = newError(secret, 1)                  // the builtin package's constructor
	fail := func(format string, args ...any) error { return fmt.Errorf(format, args...) }
	_ = fail(secret)                         // a wrapper handed a variable
	_ = fail("ok %d", 1)                     // allowed
	_ = fmt.Sprintf("%s", secret)            // allowed: the plaintext is an argument, not the format
	_ = fmt.Sprintf(note)                    // allowed: a declared constant
	_ = fmt.Fprintf(nil, "%d", 1)            // allowed
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "probe.go", source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var got []int
	for _, f := range scanDisclosureSource(fset, "probe.go", file) {
		got = append(got, f.line)
	}
	want := []int{8, 9, 10, 11, 13}
	if len(got) != len(want) {
		t.Fatalf("the guard flagged lines %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("the guard flagged lines %v, want %v", got, want)
		}
	}
}
