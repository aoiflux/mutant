package analyzer

// roleLiteral reports a role the run time refuses, written as the `role` in
// case_open's or ledger_open's options: a word that is not one of the fixed
// roles, a recipient role -- legal, external_partner, restricted_viewer --
// which names who a grant is issued to and not who is running the program, or
// "unasserted", which is what is recorded when no role is given.
//
// A role is asserted, never authenticated, and the run time refuses these three
// so that the record stays consistent with the role it names. The refusal
// comes when the program runs, after it may have asked for a passphrase; this
// rule gives the same sentence at the line. The roles an examiner is assigned
// or a recipient is named under -- case_assign's, role_define's, role_assign's
// -- are parameters that declare the words they take, and builtinArgChoice
// reports those.
//
// It reads builtin.RoleOptionBuiltins and repeats builtin.ExaminerRoleRefusal,
// the run time's own sentence, which a test in the builtin package holds to
// both builtins. It fires only on a role written as a string literal, or a name
// bound once to one, under the one `role` key of a hash literal written in the
// call or bound once in its scope.

import (
	"fmt"

	mast "mutant/ast"
	"mutant/builtin"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func lintRoleLiteral(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}
	severity, ok := lintConfig.severityForRule("roleLiteral")
	if !ok {
		return nil
	}
	takers := make(map[string]struct{})
	for _, name := range builtin.RoleOptionBuiltins() {
		takers[name] = struct{}{}
	}

	statements := snapshot.Program.Statements
	source := "mutant-lint"
	var result []lsp.Diagnostic

	forEachBuiltinCall(statements, namesBoundAnywhere(statements),
		func(name string, anchor mast.Node, call *mast.CallExpression, bindings map[string]mast.Expression) {
			if _, takes := takers[name]; !takes {
				return
			}
			hash := optionsHashLiteral(name, call, bindings)
			if hash == nil {
				return
			}
			// A `role` key written twice is refused by the parser, so a literal
			// that gets here names it at most once. The count is still checked:
			// `keys != 1` also covers a literal that names no role at all, and a
			// program the parser has refused still reaches the lint, because the
			// editor lints what is on screen.
			var role mast.Expression
			keys := 0
			for _, pair := range hash.Pairs {
				if text, literal := literalString(pair.Key); literal && text == "role" {
					role = pair.Value
					keys++
				}
			}
			if keys != 1 || role == nil {
				return
			}
			word, literal := literalString(resolveOneHop(role, bindings))
			if !literal {
				return
			}
			refusal := builtin.ExaminerRoleRefusal(word)
			if refusal == "" {
				return
			}
			rng, found := snapshot.Program.RangeOf(role)
			if !found {
				return
			}
			result = append(result, lsp.Diagnostic{
				Range:    snapshot.Range(rng),
				Severity: severity,
				Source:   &source,
				Message:  fmt.Sprintf("`%s` refuses this role: %s.", name, refusal),
			})
		})

	return result
}
