package policy

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// repositoryRoot is relative to this package's directory, which is where `go
// test` runs from.
const repositoryRoot = ".."

// policyDoc is named in every failure message so the reader learns the rule and
// not merely that they broke it.
const policyDoc = "docs/CONFIGURATION_POLICY.md"

// skippedDirs are pruned during the walk. node_modules is not optional: it
// vendors third-party Go that has nothing to do with this policy.
var skippedDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	".codegraph":   true,
	"dist":         true,
}

// mutantEnvName matches a Mutant-prefixed environment variable name. It is
// anchored, so the two known false positives need no allowlist entry: the
// MUTANT_LANGUAGE_REFERENCE.md mention in cmd/gendocs/sections.go sits inside a
// much larger literal (and "." is outside the character class), and the one in
// lsp/internal/analyzer is a comment, which is absent from the AST because we do
// not pass parser.ParseComments.
//
// The star rather than a plus is deliberate: it catches `"MUTANT_" + name` too.
var mutantEnvName = regexp.MustCompile(`^MUTANT_[A-Z0-9_]*$`)

// envFuncs are the selectors that read or write the process environment.
// Matching the selector alone -- not the package qualifier -- catches os.Getenv,
// syscall.Getenv, t.Setenv, an aliased import, and proc.Environ() on a
// gopsutil process, all with one rule.
var envFuncs = map[string]bool{
	"Getenv":    true,
	"LookupEnv": true,
	"Setenv":    true,
	"Unsetenv":  true,
	"ExpandEnv": true,
	"Environ":   true,
	"Clearenv":  true,
}

type finding struct {
	file string // repo-relative, forward slashes
	line int
	fn   string // enclosing top-level func, "" at package level
	what string
}

func (f finding) String() string {
	where := f.fn
	if where == "" {
		where = "package level"
	}
	return fmt.Sprintf("%s:%d (%s): %s", f.file, f.line, where, f.what)
}

// scan walks the repository once and returns every Mutant-prefixed name literal
// and every environment access it finds, plus the set of files it read.
func scan(t *testing.T) (names []finding, access []finding, scanned map[string]bool) {
	t.Helper()

	scanned = map[string]bool{}
	fset := token.NewFileSet()

	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}

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
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		scanned[rel] = true

		// go/parser reads build-tagged files regardless of the host GOOS, which
		// is essential here: most detection code lives behind
		// //go:build windows|linux|darwin, and a go/types or go/packages checker
		// would silently skip two thirds of it.
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}

		funcs := functionSpans(file)
		enclosing := func(pos token.Pos) string {
			for _, fn := range funcs {
				if pos >= fn.start && pos <= fn.end {
					return fn.name
				}
			}
			return ""
		}

		seen := map[int]bool{} // dedupe access findings by line
		addAccess := func(pos token.Pos, what string) {
			line := fset.Position(pos).Line
			if seen[line] {
				return
			}
			seen[line] = true
			access = append(access, finding{rel, line, enclosing(pos), what})
		}

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.BasicLit:
				if node.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(node.Value)
				if err != nil {
					return true
				}
				if mutantEnvName.MatchString(value) {
					pos := fset.Position(node.Pos())
					names = append(names, finding{rel, pos.Line, enclosing(node.Pos()), value})
				}

			case *ast.SelectorExpr:
				// Walking every SelectorExpr rather than only CallExpr.Fun is what
				// catches the function-value shape, where the function is passed
				// rather than called: addWindowsEnvIndicators(os.LookupEnv, add).
				if envFuncs[node.Sel.Name] {
					addAccess(node.Pos(), node.Sel.Name)
				}

			case *ast.ImportSpec:
				// A dot-import would make os.Getenv appear as a bare Ident, which
				// the SelectorExpr rule structurally cannot see.
				if node.Name != nil && node.Name.Name == "." {
					path, err := strconv.Unquote(node.Path.Value)
					if err == nil && (path == "os" || path == "syscall") {
						addAccess(node.Pos(), "dot-import of "+path)
					}
				}

			case *ast.AssignStmt:
				// Assignment only. The fn.Env / macro.Env *reads* in evaluator/ are
				// not environment access, and must not fire.
				for _, lhs := range node.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "Env" {
						addAccess(sel.Pos(), "assignment to .Env")
					}
				}

			case *ast.CompositeLit:
				// Narrowed to a Cmd literal so object.Function{Env: env} does not
				// fire. A locally defined struct with an Env field would be missed,
				// but any such construction still needs an os.Environ() the
				// SelectorExpr rule catches.
				if !isCmdType(node.Type) {
					return true
				}
				for _, elt := range node.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Env" {
						addAccess(kv.Pos(), "Env field in a Cmd literal")
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}

	// Two sanity checks, so a broken walk fails loudly rather than passing
	// vacuously.
	if len(scanned) == 0 {
		t.Fatalf("scanned no .go files under %s -- the walk is looking in the wrong place", root)
	}
	if !scanned["security/sandbox_windows.go"] {
		t.Fatalf("security/sandbox_windows.go was not scanned -- build-tagged files are being skipped, " +
			"which would hide most of the detection code this guard exists to bound")
	}

	return names, access, scanned
}

type funcSpan struct {
	name  string
	start token.Pos
	end   token.Pos
}

// functionSpans precomputes top-level function extents so a finding inside a
// closure attributes to the function that contains it.
func functionSpans(file *ast.File) []funcSpan {
	var spans []funcSpan
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		spans = append(spans, funcSpan{fn.Name.Name, fn.Pos(), fn.End()})
	}
	return spans
}

func isCmdType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.Ident:
		return strings.HasSuffix(t.Name, "Cmd")
	case *ast.SelectorExpr:
		return strings.HasSuffix(t.Sel.Name, "Cmd")
	case *ast.StarExpr:
		return isCmdType(t.X)
	}
	return false
}

// Rule 1. A Mutant-prefixed variable name in Go source is exactly what leads
// someone to try setting it. There is no allowlist for this one.
func TestNoMutantEnvironmentVariableNames(t *testing.T) {
	names, _, _ := scan(t)
	if len(names) == 0 {
		return
	}

	sort.Slice(names, func(i, j int) bool {
		if names[i].file != names[j].file {
			return names[i].file < names[j].file
		}
		return names[i].line < names[j].line
	})

	var b strings.Builder
	fmt.Fprintf(&b, "%d Mutant-prefixed environment variable name(s) in Go source:\n", len(names))
	for _, n := range names {
		fmt.Fprintf(&b, "  %s\n", n)
	}
	fmt.Fprintf(&b, "\nMutant takes no configuration from environment variables -- use a CLI flag.\n"+
		"This rule has no allowlist. See %s.", policyDoc)
	t.Fatal(b.String())
}

// Rules 2-5. Reading or writing the environment is permitted only where the
// value is observed rather than obeyed, and only at the sites recorded in
// EnvAccessAllowlist.
func TestNoEnvironmentAccessOutsideAllowlist(t *testing.T) {
	_, access, _ := scan(t)

	type key struct{ file, fn string }
	allowed := map[key]EnvAccessException{}
	for _, entry := range EnvAccessAllowlist {
		allowed[key{entry.File, entry.Func}] = entry
	}

	counts := map[key]int{}
	var unexpected []finding
	for _, a := range access {
		k := key{a.file, a.fn}
		if _, ok := allowed[k]; !ok {
			unexpected = append(unexpected, a)
			continue
		}
		counts[k]++
	}

	if len(unexpected) > 0 {
		sort.Slice(unexpected, func(i, j int) bool {
			if unexpected[i].file != unexpected[j].file {
				return unexpected[i].file < unexpected[j].file
			}
			return unexpected[i].line < unexpected[j].line
		})

		var b strings.Builder
		fmt.Fprintf(&b, "%d environment access(es) outside policy.EnvAccessAllowlist:\n", len(unexpected))
		for _, u := range unexpected {
			fmt.Fprintf(&b, "  %s\n", u)
		}
		fmt.Fprintf(&b, "\nMutant takes no configuration from environment variables. An access is\n"+
			"permitted only in one of three categories:\n"+
			"  detection -- Mutant observing where it is running (sandbox, VM, debugger)\n"+
			"  evidence  -- Mutant reporting on a subject process\n"+
			"  toolchain -- writing GOOS/GOARCH/CGO_ENABLED for a child `go build`\n"+
			"If this is configuration, use a CLI flag. If it is one of the three, add an\n"+
			"entry to policy.EnvAccessAllowlist and say why in the commit. See %s.", policyDoc)
		t.Fatal(b.String())
	}

	for k, entry := range allowed {
		got := counts[k]
		if got == entry.Lines {
			continue
		}
		t.Errorf("%s: %s touches the environment on %d line(s), but policy.EnvAccessAllowlist pins %d.\n"+
			"Failing here is not a defect -- it means update policy.EnvAccessAllowlist and say why in the\n"+
			"commit. Reason on record: %s\nSee %s.",
			k.file, k.fn, got, entry.Lines, entry.Why, policyDoc)
	}
}

// A renamed or deleted function must not leave a permanent hole in the guard.
func TestEnvAllowlistHasNoStaleEntries(t *testing.T) {
	_, access, scanned := scan(t)

	matched := map[string]bool{}
	for _, a := range access {
		matched[a.file+"::"+a.fn] = true
	}

	for _, entry := range EnvAccessAllowlist {
		if matched[entry.File+"::"+entry.Func] {
			continue
		}
		if !scanned[entry.File] {
			t.Errorf("policy.EnvAccessAllowlist names %s, which no longer exists. Remove the entry.", entry.File)
			continue
		}
		t.Errorf("policy.EnvAccessAllowlist allows %s in %s, but nothing there touches the environment.\n"+
			"The function was probably renamed or the access removed; either way the entry is now a hole\n"+
			"in the guard. Remove or update it. See %s.", entry.Func, entry.File, policyDoc)
	}
}

// Every entry must be classified, so a reader can tell at a glance which of the
// three arguments is being made.
func TestEnvAllowlistEntriesAreWellFormed(t *testing.T) {
	valid := map[string]bool{"detection": true, "evidence": true, "toolchain": true}
	seen := map[string]bool{}

	for _, entry := range EnvAccessAllowlist {
		id := entry.File + "::" + entry.Func
		if seen[id] {
			t.Errorf("policy.EnvAccessAllowlist has two entries for %s", id)
		}
		seen[id] = true

		if !valid[entry.Category] {
			t.Errorf("%s: category %q is not one of detection, evidence, toolchain", id, entry.Category)
		}
		if entry.Lines < 1 {
			t.Errorf("%s: Lines is %d; an entry that permits nothing should be deleted", id, entry.Lines)
		}
		if strings.TrimSpace(entry.Why) == "" {
			t.Errorf("%s: Why is empty. An exception without a justification is not reviewable.", id)
		}
		if filepath.ToSlash(entry.File) != entry.File {
			t.Errorf("%s: File must use forward slashes", entry.File)
		}
	}
}

// The guard must actually be able to see the tree it is guarding. This is
// separate from the in-scan sanity checks so a wrong repositoryRoot reports as
// its own failure rather than as a flood of stale-entry errors.
func TestGuardScansTheRepository(t *testing.T) {
	_, _, scanned := scan(t)

	for _, want := range []string{
		"main.go",
		"runner/runner.go",
		"security/sandbox_windows.go",
		"security/sandbox_linux.go",
		"security/sandbox_darwin.go",
		"policy/env_policy.go",
	} {
		if !scanned[want] {
			t.Errorf("the guard did not scan %s", want)
		}
	}

	if _, err := os.Stat(filepath.Join(repositoryRoot, policyDoc)); err != nil {
		t.Errorf("every failure message points at %s, which is missing: %v", policyDoc, err)
	}
}
