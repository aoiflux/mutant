package policy

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The workspace index is allowed to know where names are written. It is not
// allowed to decide what they mean.
//
// It used to do both, and the second half was guesswork: UniqueTopLevelDefinition
// answered "where is this declared?" by matching the string against every
// indexed document, and ReferenceLocations answered "where else is it used?" the
// same way. Neither knew what an import was. Go-to-definition jumped into
// modules nothing had imported, `_private` resolved across files the compiler
// refuses, and two modules legally declaring one name made both unresolvable.
//
// The rule that replaced them is not a naming convention and cannot be kept by
// remembering it, so it is stated as something the compiler's own AST can be
// asked: an answer about *where a name is, in some other file* has to be
// computed with the thing that knows what an import binds.

// crossFileAnswer is a return type that names a place in a file. A method of the
// index returning one is claiming a name resolves somewhere, which is exactly
// the claim that needs the import graph behind it.
var crossFileAnswer = map[string]bool{
	"Location": true,
}

// TestTheIndexCannotAnswerAboutAnotherFileWithoutSema is how the fix stays fixed
// in a repository with no CI.
//
// WorkspaceSymbols is exempt by construction rather than by allowlist: it
// returns SymbolInformation, not a Location, because it is a global fuzzy query
// -- "what exists anywhere with this in its name" -- and makes no claim that any
// of its answers is what the cursor refers to. That distinction is the whole
// point, so it is left to the type to express.
func TestTheIndexCannotAnswerAboutAnotherFileWithoutSema(t *testing.T) {
	offenders := make([]string, 0, 2)

	forEachGoFile(t, filepath.Join(repositoryRoot, "lsp", "internal", "workspace"),
		func(path string, file *ast.File, fset *token.FileSet) {
			for _, decl := range file.Decls {
				fn, isFunc := decl.(*ast.FuncDecl)
				if !isFunc || fn.Recv == nil || !fn.Name.IsExported() {
					continue
				}
				if !returnsCrossFileAnswer(fn) || takesWorkspace(fn) {
					continue
				}
				offenders = append(offenders, filepath.ToSlash(path)+":"+
					fset.Position(fn.Pos()).String()[len(path)+1:]+" "+fn.Name.Name)
			}
		})

	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("the workspace index answers about a location without sema, at:\n  %s\n\n"+
			"A method that hands back an lsp.Location is saying \"the name at your\n"+
			"cursor is declared, or used, there\". Across files that is a question\n"+
			"about what an import binds, and this package does not know. Answering it\n"+
			"by matching spellings is what made go-to-definition jump into modules\n"+
			"nothing had imported. Take a *sema.Workspace and ask it.",
			strings.Join(offenders, "\n  "))
	}
}

// returnsCrossFileAnswer reports whether fn hands back an lsp.Location, in any
// of the shapes Go can spell one: a value, a pointer, or a slice of either.
func returnsCrossFileAnswer(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}
	found := false
	for _, result := range fn.Type.Results.List {
		ast.Inspect(result.Type, func(node ast.Node) bool {
			selector, isSelector := node.(*ast.SelectorExpr)
			if isSelector && crossFileAnswer[selector.Sel.Name] {
				found = true
			}
			return !found
		})
	}
	return found
}

// takesWorkspace reports whether fn is handed the thing that knows what an
// import binds.
func takesWorkspace(fn *ast.FuncDecl) bool {
	if fn.Type.Params == nil {
		return false
	}
	found := false
	for _, param := range fn.Type.Params.List {
		ast.Inspect(param.Type, func(node ast.Node) bool {
			selector, isSelector := node.(*ast.SelectorExpr)
			if isSelector && selector.Sel.Name == "Workspace" {
				if pkg, isIdent := selector.X.(*ast.Ident); isIdent && pkg.Name == "sema" {
					found = true
				}
			}
			return !found
		})
	}
	return found
}
