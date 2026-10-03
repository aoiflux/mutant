package policy

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// One rule about where a name becomes a builtin, enforced by reading the source
// rather than by remembering.
//
// The verified root cause of the macro-expansion capability hole was not that
// somebody wrote a bad check. It was that there were TWO places where a name
// became a builtin -- evalIdentifier, and the namespace fold in
// evalFieldExpression -- and a reader looking at either one had no way to know
// about the other. The fix routes both through evaluator.resolveBuiltin, which is
// where the macro-expansion refusal lives. A third one added later would reopen
// the hole in exactly the same way, silently, and no behavioural test would
// notice: the new door would simply not be covered.
//
// So this guard is about structure, not behaviour, and it is spelled against
// every way the registry can be reached rather than against one spelling of one
// of them. A guard a rename defeats does not prevent the third door.

// builtinResolutionFile is the one file in package evaluator allowed to turn a
// name into a builtin.
const builtinResolutionFile = "eval_builtin.go"

// registryReaches are the ways package builtin hands out a *BuiltIn for a name.
// Every one of them is a door, and all of them belong behind resolveBuiltin.
var registryReaches = []string{
	"Builtins",
	"GetBuiltinByName",
	"ResolveName",
	"ResolveNames",
	"ResolveLegacyOrdinals",
}

// TestTheEvaluatorResolvesEveryBuiltinInOnePlace keeps the tree-walking engine to
// a single door into the builtin registry.
func TestTheEvaluatorResolvesEveryBuiltinInOnePlace(t *testing.T) {
	const instruction = "\n\nA macro body is evaluated by this package while the compiler is running, so " +
		"every name that becomes a builtin has to pass the macro-expansion check in " +
		"evaluator.resolveBuiltin. Route the lookup through resolveBuiltin instead. If it genuinely " +
		"belongs somewhere else, move it into " + builtinResolutionFile + " and widen resolveBuiltin, " +
		"so the policy stays written once. The hole this guards against was a SECOND door nobody " +
		"knew about, not a wrong check."

	var indexExpressions int

	forEachGoFile(t, filepath.Join(repositoryRoot, "evaluator"), func(path string, file *ast.File, fset *token.FileSet) {
		here := filepath.Base(path)
		allowed := here == builtinResolutionFile

		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.Ident:
				// The package-level map itself, under whatever name it is read.
				if n.Name == "builtins" && !allowed {
					t.Errorf("%s:%d reads the builtins map directly.%s",
						here, fset.Position(n.Pos()).Line, instruction)
				}
				// A second map built from the registry is the likeliest third
				// door, because the first one is built exactly this way.
				if n.Name == "buildBuiltinMap" && !allowed {
					t.Errorf("%s:%d builds a second builtin map.%s",
						here, fset.Position(n.Pos()).Line, instruction)
				}
			case *ast.SelectorExpr:
				pkg, isIdent := n.X.(*ast.Ident)
				if !isIdent || pkg.Name != "builtin" {
					return true
				}
				for _, reach := range registryReaches {
					if n.Sel.Name == reach && !allowed {
						t.Errorf("%s:%d calls builtin.%s, which hands out a builtin for a name.%s",
							here, fset.Position(n.Pos()).Line, reach, instruction)
					}
				}
			case *ast.IndexExpr:
				if ident, isIdent := n.X.(*ast.Ident); isIdent && ident.Name == "builtins" && allowed {
					indexExpressions++
				}
			}
			return true
		})
	})

	// The other half: the one allowed file must hold exactly one lookup. Two
	// would mean a sibling of resolveBuiltin had been added next to it, which is
	// the same hole one directory shallower.
	if indexExpressions != 1 {
		t.Errorf("%s holds %d lookups in the builtins map, want exactly 1 (the one in resolveBuiltin).%s",
			builtinResolutionFile, indexExpressions, instruction)
	}
}

// TestTheMacroRefusalSaysWhatTheRegistrySays keeps the words the expander prints
// and the words the table holds from drifting apart. The evaluator must not carry
// its own copy of a reason.
func TestTheMacroRefusalSaysWhatTheRegistrySays(t *testing.T) {
	var sawRefusal bool

	forEachGoFile(t, filepath.Join(repositoryRoot, "evaluator"), func(path string, file *ast.File, fset *token.FileSet) {
		here := filepath.Base(path)
		ast.Inspect(file, func(node ast.Node) bool {
			lit, isLit := node.(*ast.BasicLit)
			if !isLit || !strings.Contains(lit.Value, "not available at macro expansion time") {
				return true
			}
			if here != builtinResolutionFile {
				t.Errorf("%s:%d writes the macro refusal itself; it belongs in %s, "+
					"where builtin.MacroRefusal supplies the reason",
					here, fset.Position(lit.Pos()).Line, builtinResolutionFile)
				return true
			}
			sawRefusal = true
			return true
		})
	})

	if !sawRefusal {
		t.Errorf("%s no longer refuses anything at macro expansion time; if the refusal moved, "+
			"move this guard with it", builtinResolutionFile)
	}
}
