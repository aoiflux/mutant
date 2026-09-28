package analyzer

// lifecycleState reports a case_transition target that case_transition never
// moves a case to.
//
// Each move of a case's lifecycle is made by one builtin (builtin.CaseMoves):
// case_transition activates a registered case, reopens a concluded one and
// disposes of a retained one, while review_request puts a case in review,
// review_decide concludes or reopens it, and retention_set retains it. Asked
// for any other state, case_transition refuses whatever state the case is in --
// the case is already there, the lifecycle has no such move, or another builtin
// makes it -- so the call cannot succeed, and the run time says so only once the
// program has got that far. This rule says so at the argument, and which
// builtin makes the move.
//
// A word that is not a state at all is builtinArgChoice's: case_transition's
// parameter declares the states. This rule fires only on a state, written as a
// string literal or bound once to one, and compares the way case_transition
// does.

import (
	"fmt"
	"strings"

	mast "mutant/ast"
	"mutant/builtin"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func lintLifecycleState(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}
	severity, ok := lintConfig.severityForRule("lifecycleState")
	if !ok {
		return nil
	}
	params, ok := builtin.ParamSpecs(builtin.BuiltinNameCaseTransition)
	if !ok || len(params) < 2 {
		return nil
	}
	moves := builtin.CaseMoves()

	statements := snapshot.Program.Statements
	source := "mutant-lint"
	var result []lsp.Diagnostic

	forEachBuiltinCall(statements, namesBoundAnywhere(statements),
		func(name string, anchor mast.Node, call *mast.CallExpression, bindings map[string]mast.Expression) {
			if name != builtin.BuiltinNameCaseTransition || !argumentCountFitsParams(params, len(call.Arguments)) {
				return
			}
			argument := argumentAt(call, 1)
			if argument == nil {
				return
			}
			word, literal := literalString(resolveOneHop(argument, bindings))
			if !literal {
				return
			}
			state, isState := params[1].Choice(word)
			if !isState {
				return
			}
			var made []string
			startsHere := false
			for _, move := range moves {
				if move.To == state && move.By == name {
					return
				}
				if move.To == state {
					made = append(made, fmt.Sprintf("%s moves a case from %s to %s", move.By, move.From, state))
				}
				if move.From == state {
					startsHere = true
				}
			}
			how := fmt.Sprintf("no move of the lifecycle leads to %s", state)
			switch {
			case len(made) > 0:
				how = strings.Join(made, "; ")
			case startsHere:
				how = fmt.Sprintf("a case starts out %s, and no move leads back to it", state)
			}
			rng, found := snapshot.Program.RangeOf(argument)
			if !found {
				return
			}
			result = append(result, lsp.Diagnostic{
				Range:    localprotocol.ToLSPRange(rng),
				Severity: severity,
				Source:   &source,
				Message: fmt.Sprintf("`%s` never moves a case to %s, so the call is refused whatever state the case "+
					"is in: %s.", name, state, how),
			})
		})

	return result
}
