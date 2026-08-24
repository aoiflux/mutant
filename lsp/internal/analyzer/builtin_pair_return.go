package analyzer

// Mutant's fallible builtins return a (value, err) MULTI_VALUE, and binding one
// name to such a call stores the *whole pair* in that name rather than the
// value. Nothing complains: the pair prints as its value, so the program looks
// right until the name reaches something that cares about its type, and then it
// either fails far from the line that caused it or silently does nothing.
//
// This is the mirror of builtinSingleReturn, which catches the same mistake from
// the other side (two names bound from a builtin that returns one value). That
// rule was worth building because the mistake had shipped in 36 places; this one
// was written after the same defect was found in two example programs that had
// been passing for as long as anyone had been looking:
//
//	let conn = serve_conn();              // is_null(conn) is never true
//	let package_seed = json_stringify(h); // fs_write is handed a MULTI_VALUE
//
// 286 of the 409 builtins return a pair, so this is the larger half of the
// standard library and the rule sees a lot of code. That makes staying quiet on
// correct code the first requirement, not the second.
//
// Holding a pair deliberately is legal and does happen, so the rule declines
// whenever the program does anything with the name that only makes sense for a
// pair -- see namesHeldAsPairs. All three of those forms were run through the VM
// before being written down there, because a guard for an idiom that does not
// actually work would be silently suppressing real defects.

import (
	"fmt"

	mast "mutant/ast"
	"mutant/builtin"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// pairBindingCandidate is one `let x = f();` whose callee is a builtin declared
// to return a pair. It is a candidate rather than a diagnostic because whether
// it is a defect depends on what the rest of the program does with the name,
// which is not known until the walk that found it has finished.
type pairBindingCandidate struct {
	name        *mast.Identifier
	builtinName string
	kinds       string
}

// checkSingleNameBinding records `let x = f();` when f is a pair-returning
// builtin. It shares builtinCallCollector's scope walk, so it inherits the
// guards that make the other two rules false-positive-free: the callee must not
// be shadowed by a binding in scope, must be live in builtin.Builtins, and must
// carry a verified return contract.
func (c *builtinCallCollector) checkSingleNameBinding(name *mast.Identifier, value mast.Expression, current *declarationScope) {
	if c == nil || c.pairSeverity == nil || name == nil || value == nil {
		return
	}
	// `_` is the language's discard: an author writing it is saying they want
	// neither half, which is a different statement from wanting the first one.
	if name.Value == "" || name.Value == "_" {
		return
	}

	call, ok := value.(*mast.CallExpression)
	if !ok || call.Function == nil {
		return
	}
	ident, ok := call.Function.(*mast.Identifier)
	if !ok || ident.Value == "" {
		return
	}
	// A user/local binding of this name shadows the builtin.
	if _, shadowed := current.find(ident.Value); shadowed {
		return
	}
	if _, live := c.builtins[ident.Value]; !live {
		return
	}

	spec, declared := builtin.ReturnSpec(ident.Value)
	if !declared || !spec.Pair {
		return
	}

	c.pairCandidates = append(c.pairCandidates, pairBindingCandidate{
		name:        name,
		builtinName: ident.Value,
		kinds:       spec.KindsText(),
	})
}

// pairBindingDiagnostics turns the candidates the walk collected into
// diagnostics, dropping every name the program goes on to treat as a pair.
func pairBindingDiagnostics(snapshot *Snapshot, severity *lsp.DiagnosticSeverity, source *string, candidates []pairBindingCandidate) []lsp.Diagnostic {
	if len(candidates) == 0 || snapshot == nil || snapshot.Program == nil {
		return nil
	}

	held := namesHeldAsPairs(snapshot.Program.Statements)

	result := make([]lsp.Diagnostic, 0, len(candidates))
	for _, candidate := range candidates {
		if _, deliberate := held[candidate.name.Value]; deliberate {
			continue
		}
		rng, ok := snapshot.Program.RangeOf(candidate.name)
		if !ok {
			continue
		}
		result = append(result, lsp.Diagnostic{
			Range:    localprotocol.ToLSPRange(rng),
			Severity: severity,
			Source:   source,
			Message: fmt.Sprintf(
				"%s returns a (value, err) pair, so `%s` holds the pair itself and not the %s it carries. Bind two names: `let %s, err = %s(...);`",
				candidate.builtinName, candidate.name.Value, carriedValue(candidate.kinds),
				candidate.name.Value, candidate.builtinName),
		})
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

// carriedValue names the half of the pair the author meant to bind. A builtin
// whose success value can be any type -- serve_arg hands back whatever net_serve
// was given -- has no kind worth naming, and "not the ANY it carries" reads like
// a bug in the message rather than a description of one in the code.
func carriedValue(kinds string) string {
	if kinds == string(builtin.ParamAny) {
		return "value"
	}
	return kinds
}

// namesHeldAsPairs collects every name the program uses in a way that only makes
// sense for a value that really is a MULTI_VALUE. A name in this set is one the
// author is holding on purpose, so the rule says nothing about where it was
// bound.
//
// There are exactly three such forms, and each was confirmed against the VM
// rather than assumed:
//
//	let r = json_stringify(h); putln(r[0]);       // read a slot out of the pair
//	let f = fn(h) { return json_stringify(h); };  // forward the pair outward
//	let r = json_stringify(h); let a, b = r;      // destructure it later
//
// The set is keyed by name alone, with no scope resolution. Two different
// variables sharing a name therefore silence each other, which costs a report
// this rule would otherwise make and cannot cause one it should not.
//
// Passing the name to a function is deliberately *not* on this list. That is
// what `fs_write(path, package_seed)` did in dependency_version_auditor.mut,
// where the pair went in whole and the file was silently never written.
func namesHeldAsPairs(statements []mast.Statement) map[string]struct{} {
	held := make(map[string]struct{}, 4)

	hold := func(expr mast.Expression) {
		if ident, ok := expr.(*mast.Identifier); ok && ident.Value != "" {
			held[ident.Value] = struct{}{}
		}
	}

	// Both walks guard each case against a nil node of its own type. An absent
	// `else` branch is a nil *BlockStatement, and a nil pointer stored in a
	// Statement/Expression interface is not an untyped nil -- `case nil` does not
	// catch it, and the case body then dereferences it. That is not theoretical:
	// it panicked on the first real program this rule was pointed at.
	var walkStatement func(mast.Statement)
	var walkExpression func(mast.Expression)

	walkExpression = func(expr mast.Expression) {
		switch node := expr.(type) {
		case nil:
			return
		case *mast.IndexExpression:
			if node == nil {
				return
			}
			// r[0] / r[1]. The index is not examined: an index on a pair is the
			// only reading of it that makes sense, and a bad index there is a
			// separate mistake this rule has no business reporting.
			hold(node.Left)
			walkExpression(node.Left)
			walkExpression(node.Index)
		case *mast.CallExpression:
			if node == nil {
				return
			}
			walkExpression(node.Function)
			for _, arg := range node.Arguments {
				walkExpression(arg)
			}
		case *mast.FunctionLiteral:
			if node == nil {
				return
			}
			walkStatement(node.Body)
		case *mast.MacroLiteral:
			if node == nil {
				return
			}
			walkStatement(node.Body)
		case *mast.InfixExpression:
			if node == nil {
				return
			}
			walkExpression(node.Left)
			walkExpression(node.Right)
		case *mast.PrefixExpression:
			if node == nil {
				return
			}
			walkExpression(node.Right)
		case *mast.AssignExpression:
			if node == nil {
				return
			}
			walkExpression(node.Left)
			walkExpression(node.Value)
		case *mast.FieldExpression:
			if node == nil {
				return
			}
			walkExpression(node.Left)
		case *mast.ArrayLiteral:
			if node == nil {
				return
			}
			for _, element := range node.Elements {
				walkExpression(element)
			}
		case *mast.HashLiteral:
			if node == nil {
				return
			}
			for key, value := range node.Pairs {
				walkExpression(key)
				walkExpression(value)
			}
		case *mast.StructLiteral:
			if node == nil {
				return
			}
			for _, field := range node.Fields {
				if field != nil {
					walkExpression(field.Value)
				}
			}
		case *mast.IfExpression:
			if node == nil {
				return
			}
			walkExpression(node.Condition)
			walkStatement(node.Consequence)
			walkStatement(node.Alternative)
		}
	}

	walkStatement = func(stmt mast.Statement) {
		switch node := stmt.(type) {
		case nil:
			return
		case *mast.LetStatement:
			if node == nil {
				return
			}
			// `let a, b = r;` -- taking the pair apart one statement later.
			if len(node.Names) > 1 {
				hold(node.Value)
			}
			walkExpression(node.Value)
		case *mast.ReturnStatement:
			if node == nil {
				return
			}
			// `return r;` hands the pair to the caller, which is where it gets
			// destructured. Both spellings, because a single-value return
			// populates ReturnValue rather than ReturnValues.
			for _, value := range node.ReturnValues {
				hold(value)
				walkExpression(value)
			}
			if len(node.ReturnValues) == 0 && node.ReturnValue != nil {
				hold(node.ReturnValue)
				walkExpression(node.ReturnValue)
			}
		case *mast.ExpressionStatement:
			if node == nil {
				return
			}
			walkExpression(node.Expression)
		case *mast.BlockStatement:
			if node == nil {
				return
			}
			for _, inner := range node.Statements {
				walkStatement(inner)
			}
		case *mast.ForStatement:
			if node == nil {
				return
			}
			walkStatement(node.Init)
			walkExpression(node.Condition)
			walkExpression(node.Post)
			walkStatement(node.Body)
		}
	}

	for _, stmt := range statements {
		walkStatement(stmt)
	}
	return held
}
