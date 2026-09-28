package analyzer

// filteredLedgerHandle reports the handle ledger_under_view returns passed to a
// builtin that refuses it.
//
// A handle under a view reads the ledger as that view shows it. Only the reads
// in builtin.LedgerViewReads read through one, and ledger_close drops it; every
// other builtin that takes a ledger refuses it by name -- every writer, and
// every read not yet taught to filter -- so that a builtin added later reads or
// writes the whole ledger through such a handle only once somebody decides it
// may. The refusal comes when the program runs. This rule says so at the
// argument, and what to pass instead.
//
// It asks builtin.RefusesLedgerViewHandle, which a test in the builtin package
// holds to what every builtin taking a ledger does. The handle is certain only
// written out: the `handle` entry of ledger_under_view's result -- the call
// itself, or a name bound once to it -- or a name bound once to that entry. A
// handle that went through a user function, a loop or a callback's parameter
// is not followed.

import (
	"fmt"
	"strings"

	mast "mutant/ast"
	"mutant/builtin"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func lintFilteredLedgerHandle(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}
	severity, ok := lintConfig.severityForRule("filteredLedgerHandle")
	if !ok {
		return nil
	}

	statements := snapshot.Program.Statements
	shadowed := namesBoundAnywhere(statements)
	isShadowed := func(name string) bool {
		_, taken := shadowed[name]
		return taken
	}
	source := "mutant-lint"
	var result []lsp.Diagnostic

	forEachBuiltinCall(statements, shadowed,
		func(name string, anchor mast.Node, call *mast.CallExpression, bindings map[string]mast.Expression) {
			if !builtin.RefusesLedgerViewHandle(name) {
				return
			}
			params, ok := builtin.ParamSpecs(name)
			if !ok || !argumentCountFitsParams(params, len(call.Arguments)) {
				return
			}
			finder := viewHandleFinder{bindings: bindings, isShadowed: isShadowed}
			argument := argumentAt(call, 0)
			if argument == nil || !finder.handle(argument, 0) {
				return
			}
			rng, found := snapshot.Program.RangeOf(argument)
			if !found {
				return
			}
			result = append(result, lsp.Diagnostic{
				Range:    localprotocol.ToLSPRange(rng),
				Severity: severity,
				Source:   &source,
				Message: fmt.Sprintf("`%s` does not read under a view, and argument 1 is a handle `%s` returned, so "+
					"the call is refused when it runs. Only %s read through one, and `%s` drops it. Pass the "+
					"ledger's own handle, knowing that nothing it returns is filtered.", name,
					builtin.BuiltinNameLedgerUnderView, strings.Join(builtin.LedgerViewReads(), ", "),
					builtin.BuiltinNameLedgerClose),
			})
		})

	return result
}

// viewHandleFinder follows an argument back to ledger_under_view.
type viewHandleFinder struct {
	bindings   map[string]mast.Expression
	isShadowed func(string) bool
}

// handle reports whether an expression is certainly the handle of a ledger
// under a view: the `handle` entry of ledger_under_view's result, or a name
// bound once to it.
func (f viewHandleFinder) handle(expr mast.Expression, depth int) bool {
	if expr == nil || depth > maxFollowedNames {
		return false
	}
	switch node := expr.(type) {
	case *mast.Identifier:
		if node == nil {
			return false
		}
		bound, found := f.bindings[node.Value]
		return found && f.handle(bound, depth+1)
	case *mast.IndexExpression:
		if node == nil {
			return false
		}
		key, literal := literalString(node.Index)
		return literal && key == "handle" && f.result(node.Left, depth+1)
	}
	return false
}

// result reports whether an expression is certainly ledger_under_view's
// result: the call itself, or a name bound once to it.
func (f viewHandleFinder) result(expr mast.Expression, depth int) bool {
	if expr == nil || depth > maxFollowedNames {
		return false
	}
	switch node := expr.(type) {
	case *mast.Identifier:
		if node == nil {
			return false
		}
		bound, found := f.bindings[node.Value]
		return found && f.result(bound, depth+1)
	case *mast.CallExpression:
		if node == nil {
			return false
		}
		name, _, isBuiltin := builtinCallee(node.Function, f.isShadowed)
		return isBuiltin && name == builtin.BuiltinNameLedgerUnderView
	}
	return false
}
