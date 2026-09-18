package policy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Two rules about where name resolution and storage are allowed to live,
// enforced by reading the source rather than by remembering.
//
// This repository has no CI, so a rule that is only written down is a rule that
// holds until the next person has a good reason. These fail `go test ./...`,
// which is the one thing that does get run.

// resolutionPackages are the packages that decide what a name in a Mutant
// program refers to. There is one implementation of that decision -- sema -- and
// these are its callers.
var resolutionPackages = []string{
	"compiler",
	"evaluator",
	"lsp/internal/analyzer",
	"lsp/internal/server",
}

// TestTheBuiltinFoldIsDerivedInExactlyOnePlace is the fix for commit a901ce4,
// kept fixed.
//
// `ns.member` is `ns_member`, derived rather than tabulated. That derivation
// used to be written out in the compiler, in the evaluator and twice more in the
// language server, and each site asked "is this name already taken?" of a
// different thing. Nine builtins ran under one engine, were recommended by the
// editor, and failed to compile.
//
// The giveaway is the concatenation itself: `left + "_" + field`. If it appears
// anywhere outside sema, a second answer to the question has been written.
func TestTheBuiltinFoldIsDerivedInExactlyOnePlace(t *testing.T) {
	offenders := make([]string, 0, 4)

	for _, pkg := range resolutionPackages {
		forEachGoFile(t, filepath.Join(repositoryRoot, pkg), func(path string, file *ast.File, fset *token.FileSet) {
			for _, decl := range file.Decls {
				fn, isFunc := decl.(*ast.FuncDecl)
				if !isFunc || fn.Body == nil {
					continue
				}
				if _, allowed := foldAllowlist[fn.Name.Name]; allowed {
					continue
				}
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					binary, isBinary := node.(*ast.BinaryExpr)
					if !isBinary || binary.Op != token.ADD {
						return true
					}
					if !isUnderscoreLiteral(binary.X) && !isUnderscoreLiteral(binary.Y) {
						return true
					}
					offenders = append(offenders, filepath.ToSlash(path)+":"+
						strconv.Itoa(fset.Position(node.Pos()).Line)+" in "+fn.Name.Name)
					return true
				})
			}
		})
	}

	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("the builtin fold is derived outside sema, at:\n  %s\n\n"+
			"`ns.member` is `ns_member`, and that has to be decided once. Four copies of\n"+
			"the rule is what commit a901ce4 fixed: each asked whether the name was\n"+
			"already bound, each asked a different thing, and nine builtins compiled in\n"+
			"one engine and not another. Call sema.Resolver.ResolveField instead.",
			strings.Join(offenders, "\n  "))
	}
}

// foldAllowlist names the functions that may build a `name_name` string for a
// reason that is not resolving what `a.b` refers to. Each entry states why,
// because an allowlist without reasons becomes a place to put things.
var foldAllowlist = map[string]string{
	"builtinFamilyMembers": "the inverse operation: given a family, list its members. " +
		"It derives a prefix to enumerate with, and decides nothing about any particular a.b.",
	"namesSpelledIn": "deliberately textual, and deliberately not a resolution. It asks whether a " +
		"closing call is spelled anywhere in a scope so the unclosed-resource rule can stay quiet, " +
		"and ignores shadowing on purpose -- resolving properly would make it stricter and let it " +
		"report a handle that is correctly closed, which its doc promises never to do.",
}

// isUnderscoreLiteral reports whether e is the string literal "_", which is the
// separator in a folded builtin name.
func isUnderscoreLiteral(e ast.Expr) bool {
	literal, isLiteral := e.(*ast.BasicLit)
	if !isLiteral || literal.Kind != token.STRING {
		return false
	}
	unquoted, err := strconv.Unquote(literal.Value)
	return err == nil && unquoted == "_"
}

// TestStorageStaysOffTheCompileAndKeystrokePaths keeps the graph database out of
// the packages that must answer without touching a disk.
//
// The guard is on direct imports, not on `go list -deps`, and that distinction
// is the honest one: builtin/db.go exposes the database to Mutant programs as
// builtins, and the compiler has always imported builtin, so graphene has been
// in the compiler's transitive dependency tree since long before the symbol
// graph existed. Asserting otherwise would be asserting something untrue.
//
// What must stay true is that nothing on these paths *uses* it. Name resolution
// runs inside codegen, once per field expression, and again on every keystroke:
// it has to be a map lookup against state already in memory -- no I/O, no open
// handle, no error to return. The symbol graph is written to graphene by the
// export command and read back by analysis, which is a different program at a
// different time.
func TestStorageStaysOffTheCompileAndKeystrokePaths(t *testing.T) {
	const storage = "github.com/aoiflux/graphene"

	guarded := append([]string{"sema"}, resolutionPackages...)
	offenders := make([]string, 0, 2)

	for _, pkg := range guarded {
		forEachGoFile(t, filepath.Join(repositoryRoot, pkg), func(path string, file *ast.File, _ *token.FileSet) {
			for _, imported := range file.Imports {
				unquoted, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					continue
				}
				if unquoted == storage || strings.HasPrefix(unquoted, storage+"/") {
					offenders = append(offenders, filepath.ToSlash(path)+" imports "+unquoted)
				}
			}
		})
	}

	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("a graph database reached the compile or keystroke path:\n  %s\n\n"+
			"Resolving a name happens inside codegen and again on every keystroke. It\n"+
			"must be a map lookup over state already in memory. The symbol graph is\n"+
			"exported to storage by `mutant graph export` and read back separately.",
			strings.Join(offenders, "\n  "))
	}
}

// forEachGoFile parses every non-test .go file under dir. Test files are
// excluded: a test may legitimately reach for anything to set a fixture up.
func forEachGoFile(t *testing.T, dir string, visit func(path string, file *ast.File, fset *token.FileSet)) {
	t.Helper()

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("guarded package %s is missing: %v", dir, err)
	}

	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if skippedDirs[entry.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		parsed, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		visit(path, parsed, fset)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
}

// An allowlist entry that no longer matches anything is worse than none: it
// reads as a live exemption while protecting nothing, and the next person to
// write a fold finds a rule with a hole in it and no way to tell the hole is
// stale.
func TestEveryFoldAllowlistEntryStillNamesAFunction(t *testing.T) {
	found := make(map[string]bool, len(foldAllowlist))

	for _, pkg := range resolutionPackages {
		forEachGoFile(t, filepath.Join(repositoryRoot, pkg), func(_ string, file *ast.File, _ *token.FileSet) {
			for _, decl := range file.Decls {
				if fn, isFunc := decl.(*ast.FuncDecl); isFunc {
					if _, allowed := foldAllowlist[fn.Name.Name]; allowed {
						found[fn.Name.Name] = true
					}
				}
			}
		})
	}

	for name := range foldAllowlist {
		if !found[name] {
			t.Fatalf("the fold allowlist exempts %q, which no longer exists. Remove the entry.", name)
		}
	}
}
