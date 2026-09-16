package analyzer

// A write through more than one container -- `counts[host]["n"] = 1` -- used to
// compile, run, change nothing and say nothing. The compiler now stores every
// container it passed through back where it came from, so that shape works; what
// it cannot emit, it refuses by name.
//
// This rule is the editor's half of those two refusals. Both are compile errors,
// so without it the first time anyone hears about either is a failed build, and
// the standing rule in CONTRIBUTING is that a feature is not done when the
// compiler accepts it -- it is done when the editor teaches it.
//
// It is a purely syntactic check against the same two conditions the compiler
// tests, so it cannot disagree with the compiler and cannot report a program
// that would have built:
//
//   - A target with no variable under it (`[1, 2][0] = 9`, `f()[0] = 1`) has
//     nowhere to store its result.
//   - An index before the last one is loaded again on the way back out, so
//     anything that is not a name or a literal would run more than once.

import (
	"fmt"

	mast "mutant/ast"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func lintAssignmentTargets(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}

	severity, ok := lintConfig.severityForRule("assignmentTarget")
	if !ok {
		return nil
	}

	source := "mutant-lint"
	var diagnostics []lsp.Diagnostic

	report := func(node mast.Node, message string) {
		rng, ok := snapshot.Program.RangeOf(node)
		if !ok {
			return
		}
		diagnostics = append(diagnostics, lsp.Diagnostic{
			Range:    localprotocol.ToLSPRange(rng),
			Severity: severity,
			Source:   &source,
			Message:  message,
		})
	}

	for _, stmt := range snapshot.Program.Statements {
		visitExpressions(stmt, func(expr mast.Expression) {
			assign, ok := expr.(*mast.AssignExpression)
			if !ok || assign.Left == nil {
				return
			}

			if assignmentRoot(assign.Left) == nil {
				report(assign.Left, fmt.Sprintf(
					"`%s` has no variable under it, so there is nowhere to store the result: "+
						"the write would land in a value the program drops. Bind the container to a name first.",
					assign.Left.String()))
				return
			}

			for _, step := range assignmentIndexSteps(assign.Left) {
				report(step, fmt.Sprintf(
					"`%s` is an index before the last one, so it is evaluated more than once on the way "+
						"back out and has to be a name or a literal. Bind it to a variable first.",
					step.String()))
			}
		})
	}

	return diagnostics
}

// assignmentIndexSteps returns the index expressions of target that the compiler
// re-evaluates and that are not safe to re-evaluate -- every index but the last,
// which is compiled once and is free to be anything.
func assignmentIndexSteps(target mast.Expression) []mast.Expression {
	var indexes []mast.Expression
	for {
		switch n := target.(type) {
		case *mast.IndexExpression:
			indexes = append(indexes, n.Index)
			target = n.Left
		case *mast.FieldExpression:
			target = n.Left
		default:
			// indexes came off the target outermost-first, so entry 0 is its
			// last hop -- the one the compiler compiles exactly once, and the
			// one that is therefore free to be a call.
			if len(indexes) < 2 {
				return nil
			}
			var reevaluated []mast.Expression
			for _, index := range indexes[1:] {
				if index != nil && !pureAssignmentIndex(index) {
					reevaluated = append(reevaluated, index)
				}
			}
			return reevaluated
		}
	}
}

// pureAssignmentIndex mirrors the compiler's pureAssignIndex: names and literals
// can be evaluated more than once, and a call cannot.
func pureAssignmentIndex(expr mast.Expression) bool {
	switch e := expr.(type) {
	case *mast.Identifier, *mast.IntegerLiteral, *mast.FloatLiteral, *mast.StringLiteral, *mast.Boolean:
		return true
	case *mast.IndexExpression:
		return pureAssignmentIndex(e.Left) && pureAssignmentIndex(e.Index)
	case *mast.FieldExpression:
		return pureAssignmentIndex(e.Left)
	default:
		return false
	}
}
