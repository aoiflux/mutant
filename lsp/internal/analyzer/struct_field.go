package analyzer

import (
	mast "mutant/ast"
	"mutant/object"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// A field a struct does not declare, said before the build says it.
//
// These are not lints and take no LintConfig, for the reason the module rules
// give: "struct P has no field zzz" is the language and not a matter of taste,
// and the sentence shown is the compiler's own -- object.UnknownStructFieldMessage,
// the same function both engines and the compiler call. The squiggle and the
// build error are one wording rather than two phrasings of one rule.
//
// It answers only where the receiver's type is CERTAIN. That is a narrower reach
// than Snapshot.TypeOf, which follows a struct through a function's return and
// through another binding -- and which this deliberately does not use. Those
// answers are inferred, the package's own comments call them heuristic, and an
// Error squiggle built on one is a guess presented as a fact.
//
// Certain means two things, and the division of labour is worth stating:
//
//   - WHICH declaration the receiver names is sema.Graph's answer, taken through
//     resolveDefinition. That is better than the compiler's own rule, which
//     gives up on a name bound twice anywhere in the program: the graph knows
//     the scopes, so a parameter called p shadowing a top-level p resolves to
//     the parameter and is simply not a struct literal's binding.
//   - WHETHER that declaration still holds what it was given is the one thing
//     the graph cannot say. RefRole records what a use names -- RoleUse,
//     RoleConstruct, RolePattern -- and not whether it writes, so a reassignment
//     is invisible to it. reassignedNames is that gap, closed by a walk.

// structFieldSource marks these as the compiler's refusals rather than a lint.
const structFieldSource = "mutant-structs"

// reassignedNames is every name this file assigns to.
//
// A write THROUGH a name is not one: `p.f = v` and `p[i] = v` read p and leave
// it holding what it held, which is the whole point of checking them. Only a
// bare name on the left of an assignment is a name that stopped being what it
// was declared as.
//
// Keyed by name rather than by declaration, which is conservative in the one
// direction that matters: a reassignment of some other `p` in another scope
// silences the diagnostic for every p in the file. A missing squiggle is a cost
// the author does not see; a wrong one is a cost they cannot ignore.
func (s *Snapshot) reassignedNames() map[string]bool {
	names := make(map[string]bool)
	if s == nil || s.Program == nil {
		return names
	}
	for _, stmt := range s.Program.Statements {
		visitExpressions(stmt, func(expr mast.Expression) {
			assign, isAssign := expr.(*mast.AssignExpression)
			if !isAssign || assign == nil {
				return
			}
			if base, isName := assign.Left.(*mast.Identifier); isName && base != nil {
				names[base.Value] = true
			}
		})
	}
	return names
}

// assignedFieldTargets is every `p.f` that is itself the target of an
// assignment, so that a write is reported in the words a write is reported in.
//
// Only the target itself. In `p.f[0] = v` the field expression is a read of p.f
// and the index is the write, and in `p.a.f = v` the outer expression is the
// target while `p.a` under it is a read.
func (s *Snapshot) assignedFieldTargets() map[*mast.FieldExpression]bool {
	targets := make(map[*mast.FieldExpression]bool)
	if s == nil || s.Program == nil {
		return targets
	}
	for _, stmt := range s.Program.Statements {
		visitExpressions(stmt, func(expr mast.Expression) {
			assign, isAssign := expr.(*mast.AssignExpression)
			if !isAssign || assign == nil {
				return
			}
			if target, isField := assign.Left.(*mast.FieldExpression); isField && target != nil {
				targets[target] = true
			}
		})
	}
	return targets
}

// StructFieldDiagnostics reports every `p.f` whose f the struct p holds does not
// declare.
//
// An enum access, an import namespace and a builtin fold all arrive here as
// `ident.member` too, and all three fall out at the struct check: none of them
// is a name a `let` bound from a struct literal. They are not special-cased,
// because a special case is a thing that can disagree with the precedence
// sema.ResolveField decides.
func (s *Snapshot) StructFieldDiagnostics() []lsp.Diagnostic {
	if s == nil || s.Program == nil {
		return nil
	}

	reassigned := s.reassignedNames()
	targets := s.assignedFieldTargets()

	var diagnostics []lsp.Diagnostic
	for _, field := range s.namespaceFields() {
		if reassigned[field.left] {
			continue
		}

		// The receiver's own start, which is where the field expression starts:
		// whether `p` names a struct literal's binding is a question about the
		// declaration, not about the point inside the expression.
		//
		// Asked in the AST's own coordinates rather than through a protocol
		// position, which is what startOf did before 63eb1c4 removed it: the name
		// graph counts the same 1-based line and byte column the range does, so
		// converting out and back is a round trip that M26-LSP-027 showed can be
		// wrong in both directions at once.
		declared, resolved := s.resolveDefinitionAt(field.rng.Start.Line, field.rng.Start.Column)
		if !resolved || declared.ident == nil {
			continue
		}

		typeName, isStructBinding := s.structTypeNameForDeclaration(declared.ident)
		if !isStructBinding {
			continue
		}
		names, isDeclared := s.structFieldNames(typeName)
		if !isDeclared || containsName(names, field.field) {
			continue
		}

		message := object.UnknownStructFieldMessage(typeName, field.field, names)
		if targets[field.node] {
			message = object.UnknownStructFieldWriteMessage(typeName, field.field, names)
		}

		severity := lsp.DiagnosticSeverityError
		source := structFieldSource
		diagnostics = append(diagnostics, lsp.Diagnostic{
			Range:    s.Range(field.rng),
			Severity: &severity,
			Source:   &source,
			Message:  message,
		})
	}
	return diagnostics
}

func containsName(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}
