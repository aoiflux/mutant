package analyzer

// macroSafety reports a builtin a macro body calls that the compiler refuses.
//
// A macro body is not part of the program. It runs while the compiler is
// running, in the tree-walking evaluator, and the expander allows it pure
// computation and nothing else: a builtin that reads or writes a file, reaches
// the network, starts a process, draws entropy, reads the clock, decodes
// cryptographic material or answers from state something else set is refused by
// name, with a sentence saying which of those it does. Without this rule the
// first the author hears of it is `mutant gen` failing with the macro's name and
// no line of their own to look at -- and expansion is fail-fast, so a file
// holding three such calls reports one of them per compile.
//
// It reads builtin.MacroRefusal, the function evaluator.resolveBuiltin prints
// from, so the editor cannot name a reason the compiler does not, nor report a
// builtin the expander allows. policy/macro_guard_test.go holds the expander to
// that function; the test beside this file holds these diagnostics to the
// expander itself, over the whole registry and in both spellings.
//
// What it looks at, and what it leaves alone:
//
//   - Only a macro the expander defines: a top-level `let name = macro(...) {}`.
//     evaluator.DefineMacros reads program.Statements and nothing else, so a
//     `macro` literal written inside a function is never registered, never
//     expanded, and a refusal there would never fire.
//
//   - Nothing inside `quote(...)`. What a quote holds is the source the macro
//     emits: those calls run when the emitted program runs, where the builtin is
//     ordinary. `unquote(...)` re-opens evaluation and is honoured wherever it
//     sits, inside a nested quote included, because evalUnquoteCalls rewrites the
//     whole quoted node in one pass rather than counting levels -- so this tracks
//     the two as the engine tracks them, and not as quasiquote depth.
//
//   - `quote` and `unquote` are matched on the callee's token and on an argument
//     count of exactly one, which is what the engine matches: eval intercepts a
//     call whose function's TokenLiteral is "quote" before it resolves the name,
//     and both it and evalUnquoteCalls refuse any other arity before evaluating
//     anything. Seeing fewer quotes than the engine sees would mean reporting a
//     template as though it ran, which is the one direction this must not err in.
//
//   - Direct calls only. The expander refuses through a function the body calls
//     as well -- the macro's environment carries the mark and an enclosed one
//     inherits it -- but following a name to a function body means deciding which
//     function it stands for, and a rule that guesses reports correct code. The
//     compiler still refuses there; the editor stays quiet.
//
//   - A macro nothing calls is reported all the same, which is the one place this
//     says more than the compiler does: a body runs where the macro is called, so
//     an uncalled macro refuses nothing and the build succeeds. The claim is about
//     the call, and the day the macro is called the build fails -- the body is no
//     less wrong before that. unusedDeclaration reports the macro itself.
//
// Reachability is not asked about beyond that, as it is not by platformSupport or
// weakCrypto: the claim is about this call, not about whether the program reaches
// it.

import (
	"fmt"

	mast "mutant/ast"
	"mutant/builtin"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func lintMacroSafety(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}
	severity, ok := lintConfig.severityForRule("macroSafety")
	if !ok {
		return nil
	}

	statements := snapshot.Program.Statements
	source := "mutant-lint"
	var result []lsp.Diagnostic

	for _, stmt := range statements {
		literal := macroDefinition(stmt)
		if literal == nil {
			continue
		}
		isShadowed := macroBodyShadows(statements, literal)
		forEachExpansionTimeCall(literal.Body, func(call *mast.CallExpression) {
			name, anchor, ok := builtinCallee(call.Function, isShadowed)
			if !ok || !isLiveBuiltin(name) {
				return
			}
			refusal := builtin.MacroRefusal(name)
			if refusal == "" {
				return
			}
			rng, found := snapshot.Program.RangeOf(anchor)
			if !found {
				return
			}
			result = append(result, lsp.Diagnostic{
				Range:    snapshot.Range(rng),
				Severity: severity,
				Source:   &source,
				Message: fmt.Sprintf("`%s` is not available at macro expansion time, because %s.",
					calleeSpelling(anchor, name), refusal),
			})
		})
	}

	return result
}

// macroDefinition returns the macro literal a top-level statement defines, or
// nil. It matches evaluator.isMacroDefinition: a `let` whose value is a macro
// literal, which is the only shape DefineMacros registers.
func macroDefinition(stmt mast.Statement) *mast.MacroLiteral {
	let, ok := stmt.(*mast.LetStatement)
	if !ok || let == nil {
		return nil
	}
	literal, ok := let.Value.(*mast.MacroLiteral)
	if !ok || literal == nil || literal.Body == nil {
		return nil
	}
	return literal
}

// macroBodyShadows answers whether a name might be something other than the
// builtin of that name while this macro body runs: anything the file binds, the
// macro's own parameters -- each of which holds the quoted argument the call site
// wrote -- and anything the body itself binds.
//
// The body's own bindings are collected here rather than left to
// namesBoundAnywhere, which does not walk into a macro literal: every other rule
// treats one as a template.
func macroBodyShadows(statements []mast.Statement, literal *mast.MacroLiteral) func(string) bool {
	bound := make(map[string]struct{})
	for name := range namesBoundAnywhere(statements) {
		bound[name] = struct{}{}
	}
	if literal.Body != nil {
		for name := range namesBoundAnywhere(literal.Body.Statements) {
			bound[name] = struct{}{}
		}
	}
	for _, param := range literal.Parameters {
		if param != nil && param.Value != "" {
			bound[param.Value] = struct{}{}
		}
	}
	return func(name string) bool {
		_, taken := bound[name]
		return taken
	}
}

// forEachExpansionTimeCall visits every call in a macro body that the expander
// evaluates while the compiler is running.
//
// The two states are the engine's own. In the first the body is being evaluated:
// `quote(x)` hands x to the second state and evaluates nothing in it, and
// `unquote(x)` is not a name the expander resolves at all, so that call fails
// before x is looked at. In the second the body is a template: nothing in it
// runs, except that `unquote(x)` puts x back into the first state, wherever in
// the template it sits.
//
// It is not forEachBuiltinCall or visitExpressions. Neither descends into a
// macro literal -- nor does ast.Modify, and for the same reason: a macro body is
// a template, expanded in the caller's environment rather than at its definition
// -- and neither can stop at a subtree that means something different from the
// one around it.
func forEachExpansionTimeCall(body *mast.BlockStatement, visit func(*mast.CallExpression)) {
	if body == nil {
		return
	}

	var evaluated, quoted func(mast.Node)

	evaluated = func(node mast.Node) {
		walkExpressionsFiltered(node, true, func(expr mast.Expression) bool {
			call, ok := expr.(*mast.CallExpression)
			if !ok || call == nil {
				return true
			}
			if argument, is := macroQuoteArgument(call, "quote"); is {
				if argument != nil {
					quoted(argument)
				}
				return false
			}
			if _, is := macroQuoteArgument(call, "unquote"); is {
				return false
			}
			return true
		}, func(expr mast.Expression) {
			if call, ok := expr.(*mast.CallExpression); ok && call != nil {
				visit(call)
			}
		})
	}

	quoted = func(node mast.Node) {
		walkExpressionsFiltered(node, true, func(expr mast.Expression) bool {
			call, ok := expr.(*mast.CallExpression)
			if !ok || call == nil {
				return true
			}
			if argument, is := macroQuoteArgument(call, "unquote"); is {
				if argument != nil {
					evaluated(argument)
				}
				return false
			}
			return true
		}, func(mast.Expression) {})
	}

	evaluated(body)
}

// macroQuoteArgument answers whether this call is the quote form named by word,
// and hands back the one expression it takes.
//
// The token is what the engine matches -- evaluator.Eval on "quote",
// isUnquoteCall on "unquote" -- and it matches before resolving the name, so a
// file that binds `quote` to something of its own still gets the quote form. The
// arity is the engine's too: both refuse any other count before evaluating
// anything, so such a call carries nothing that runs. It is reported as the
// form, with no argument.
func macroQuoteArgument(call *mast.CallExpression, word string) (mast.Expression, bool) {
	if call == nil || call.Function == nil || call.Function.TokenLiteral() != word {
		return nil, false
	}
	if len(call.Arguments) != 1 {
		return nil, true
	}
	return call.Arguments[0], true
}

// calleeSpelling is the name as the author wrote it. The expander's refusal
// repeats the spelling rather than the flat name -- resolveBuiltin is keyed on
// `fs_write` and reports `fs.write` -- so the author reads the words they typed,
// and this says the same.
func calleeSpelling(anchor mast.Node, flat string) string {
	field, ok := anchor.(*mast.FieldExpression)
	if !ok || field == nil || field.Field == nil {
		return flat
	}
	namespace, ok := field.Left.(*mast.Identifier)
	if !ok || namespace == nil {
		return flat
	}
	return namespace.Value + "." + field.Field.Value
}
