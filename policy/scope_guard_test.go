package policy

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// A scope chain is a linked list of name tables, and each one is a second
// answer to "what is in scope here".
//
// The language server had five walks that built one: resolveStatement and
// resolveExpression for go-to-definition, scopeAtStatement and advanceStatement
// for the bindings visible at a position, and referenceCollector for
// find-references. They shared a `scope` type and nothing else, so each of them
// re-encoded, separately, which AST nodes declare a name. Agreement between
// them was a matter of care rather than of construction, and they did not
// agree: *ast.ImportStatement appeared in none of the five, so an import alias
// was not a binding anywhere -- no definition, no references, absent from
// completion -- while the comment above the caller said otherwise.
//
// sema.Graph is that walk, once. This is the rule that keeps it at once.
//
// The giveaway is structural and needs no allowlist to be precise: a struct
// with a field pointing at its own type AND named for an enclosing scope. A
// recursive type descriptor -- analyzer.Type, whose Elem and Ret point at
// Type -- is self-referential for an unrelated reason and is not caught,
// because it does not name a parent.

// enclosingFieldNames are the field names that make a self-referential struct a
// scope chain rather than a recursive value.
var enclosingFieldNames = map[string]bool{
	"parent":    true,
	"Parent":    true,
	"outer":     true,
	"Outer":     true,
	"enclosing": true,
	"Enclosing": true,
}

// scopeChainAllowlist names the scope chains that may exist outside sema. Each
// entry states why, because an allowlist without reasons becomes a place to put
// things.
var scopeChainAllowlist = map[string]string{
	"SymbolTable": "the compiler's slot machinery, and deliberately never migrated. " +
		"sema decides WHICH DECLARATION a use refers to; the symbol table decides WHICH SLOT " +
		"that declaration lives in, and its Outer chain exists for free-variable capture -- " +
		"Define's index allocation, defineFree, markCaptured. sema must never learn what a " +
		"slot is, which is what keeps capture analysis where it belongs.",

	"typeEnv": "inference, not name resolution. It maps a name to the TYPE inferred for it, " +
		"which is per-snapshot, explicitly heuristic, and something sema refuses to hold -- a " +
		"graph the compiler reads must not contain a guess. It resolves nothing: infer.go asks " +
		"what a name is worth, never which declaration it is.",

	"declarationScope": "the last of the duplication, and named here so it is not mistaken " +
		"for a decision. One collector in diagnostics.go still walks the tree with it -- " +
		"undefinedCollector -- and re-encodes which nodes bind a VALUE, exactly as the five " +
		"deleted walks did. Its account of type names has already gone: a struct or enum name " +
		"used to be filed in this chain beside the file's lets, so `struct Point { x }; " +
		"Point;` drew no diagnostic while the build refused it with `undefined variable: " +
		"Point`. The two positions where a type name is legal -- a struct literal and an enum " +
		"value -- now ask sema.Graph, and parity/undefined_lint_parity_test.go decides every " +
		"row by compiling it.\n\n" +
		"What is left needs a decision rather than a translation, which is why it is still " +
		"here. sema.BuildFile records nothing for a name it cannot resolve, deliberately -- " +
		"see builder.reference, where inventing a reference is what starts a jump into an " +
		"unrelated file -- so there is no RefUnresolved to read this rule off, and the plan's " +
		"Ref.Kind was not built. Absorbing it means either giving the graph a record of what " +
		"it could not bind, with enough context to tell `hash.blake3` from a bare name, or " +
		"leaving this walk where it is. Until that is settled, this entry is what stops a " +
		"second being added quietly.\n\n" +
		"Two collectors went before it, and what their duplication cost is on the record. " +
		"builtinCallCollector's chain answered one question -- is this name taken here -- and " +
		"answered it differently from the compiler, because it wrote struct and enum names " +
		"into the same table as lets and parameters. A file declaring `struct fs { path; }` " +
		"lost every arity, argument-kind and deprecation check on `fs.read(...)`, silently, " +
		"while the build folded the call to fs_read and ran it. See " +
		"parity/builtin_lint_parity_test.go.\n\n" +
		"duplicateCollector's chain answered the same question by walking PARENT scopes, so " +
		"every shadow was a duplicate: a parameter named after a top-level let was reported " +
		"as a second declaration of it, and so was a struct name beside a value of that name. " +
		"Both compile, both run, and both declarations do work -- and the complaint carried a " +
		"preferred quick fix whose edit deletes one of the two lines. It now reads Seq and " +
		"Scope off the graph, and parity/duplicate_lint_parity_test.go runs every row it is " +
		"silent about, so the silence is justified by a value rather than by an opinion.",
}

func TestAScopeChainIsBuiltInExactlyOnePlace(t *testing.T) {
	offenders := make([]string, 0, 2)

	for _, pkg := range resolutionPackages {
		forEachGoFile(t, filepath.Join(repositoryRoot, pkg),
			func(path string, file *ast.File, fset *token.FileSet) {
				for _, spec := range scopeChainsIn(file) {
					if _, allowed := scopeChainAllowlist[spec.Name.Name]; allowed {
						continue
					}
					offenders = append(offenders, filepath.ToSlash(path)+":"+
						strconv.Itoa(fset.Position(spec.Pos()).Line)+" "+spec.Name.Name)
				}
			})
	}

	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("a scope chain was built outside sema, at:\n  %s\n\n"+
			"A linked list of name tables is a second answer to \"what is in scope\n"+
			"here\", and filling one in means deciding, again and separately, which\n"+
			"AST nodes declare a name. Five walks in the language server did that;\n"+
			"none of them had a case for *ast.ImportStatement, so an import alias was\n"+
			"a binding in no one's account of the file.\n\n"+
			"Ask sema.Graph: VisibleAt for what is in scope at a position, Resolve\n"+
			"for what a position refers to, UsesOf for where a declaration is used.\n"+
			"If the new chain is genuinely not resolving names -- inference has one,\n"+
			"and the compiler's symbol table has one for slot allocation -- add it to\n"+
			"scopeChainAllowlist with the reason.",
			strings.Join(offenders, "\n  "))
	}
}

// scopeChainsIn returns the struct types in a file that point at themselves
// through a field named for an enclosing scope.
func scopeChainsIn(file *ast.File) []*ast.TypeSpec {
	found := make([]*ast.TypeSpec, 0, 1)

	ast.Inspect(file, func(node ast.Node) bool {
		spec, isType := node.(*ast.TypeSpec)
		if !isType {
			return true
		}
		structure, isStruct := spec.Type.(*ast.StructType)
		if !isStruct || structure.Fields == nil {
			return true
		}
		for _, field := range structure.Fields.List {
			pointer, isPointer := field.Type.(*ast.StarExpr)
			if !isPointer {
				continue
			}
			target, isIdent := pointer.X.(*ast.Ident)
			if !isIdent || target.Name != spec.Name.Name {
				continue
			}
			for _, name := range field.Names {
				if enclosingFieldNames[name.Name] {
					found = append(found, spec)
					return true
				}
			}
		}
		return true
	})

	return found
}

// An allowlist entry that no longer matches anything reads as a live exemption
// while protecting nothing. Absorbing declarationScope into the graph should
// delete its entry, and this is what says so.
func TestEveryScopeChainAllowlistEntryStillNamesAType(t *testing.T) {
	found := make(map[string]bool, len(scopeChainAllowlist))

	for _, pkg := range resolutionPackages {
		forEachGoFile(t, filepath.Join(repositoryRoot, pkg),
			func(_ string, file *ast.File, _ *token.FileSet) {
				for _, spec := range scopeChainsIn(file) {
					if _, allowed := scopeChainAllowlist[spec.Name.Name]; allowed {
						found[spec.Name.Name] = true
					}
				}
			})
	}

	stale := make([]string, 0, 1)
	for name := range scopeChainAllowlist {
		if !found[name] {
			stale = append(stale, name)
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Fatalf("scopeChainAllowlist exempts types that no longer exist: %s\n\n"+
			"If the chain is gone, so is the reason to exempt it. Delete the entry.",
			strings.Join(stale, ", "))
	}
}
