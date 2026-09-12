package analyzer

// 334 of the 459 builtins return `(value, err)`. Binding the error and never
// looking at it is not a runtime error, is not a compile error, and produces no
// output: the program carries on with whatever the failed call left in the
// value -- null, an empty array, a zero -- and reports success. That is the
// defect L-6 opened with, and it is measured rather than assumed: 119 of the
// 669 error bindings in `examples/**` (18%) are never read.
//
// The obvious objection is that `unusedDeclaration` should already catch this.
// It does not, and the reason is worth stating because it decides the whole
// shape of this rule. Measured against the corpus before this file was written,
// the existing rule reports an unread `err` exactly **three** times in 104
// files. Two things suppress it: `err` is bound 85 times over at the top level,
// so it is a duplicate name and `lintUnusedDeclarations` skips it wholesale;
// and its reference lookup answers for the *name*, so one `if (err)` anywhere
// in the file marks every `err` in it as used.
//
// So the question this rule has to ask is not "is this name ever read" but "is
// **this binding** ever read" -- from the `let` that made it to the `let` that
// replaces it. That is the same question the 18% measurement asked ("whether
// the second name is read before it is shadowed or the file ends"), and asking
// it any other way reproduces `unusedDeclaration`'s blind spot instead of
// covering it.
//
// Asking the narrower question finds 40 reports in that corpus, every one of
// them read by hand before this shipped. It is fewer than 119 on purpose: only
// builtins whose contract is *declared* as a pair are considered, a name a
// closure mentions is excused, and a failure the program caught through the
// value rather than the error is not a failure it ignored. What is left is the
// part that can be proved from the tree.
//
// It reads `builtin.ReturnSpec` -- the same contract `builtinSingleReturn` and
// `builtinPairReturn` read -- from the opposite direction. Those two ask
// whether the binding's *shape* matches the builtin's. This one takes a binding
// whose shape is already right and asks whether the error half was used.
//
// What counts as using it is deliberately generous: tested, printed,
// propagated, passed on, stored. Any mention at all. A rule that tried to
// distinguish "handled" from "merely read" would have to decide that
// `putln(err)` is not good enough, and that is a judgement about someone's
// program rather than a fact about it. The narrow question -- bound, then never
// looked at again -- has an answer that is either yes or no.

import (
	"fmt"
	"math"

	mast "mutant/ast"
	"mutant/builtin"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func lintUncheckedErrors(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}

	severity, ok := lintConfig.severityForRule("uncheckedError")
	if !ok {
		return nil
	}

	source := "mutant-lint"
	collector := &uncheckedErrorCollector{
		snapshot: snapshot,
		severity: severity,
		source:   &source,
		shadowed: namesBoundAnywhere(snapshot.Program.Statements),
		builtins: liveBuiltinNames(),
	}
	collector.checkScope(snapshot.Program.Statements)
	return collector.result
}

type uncheckedErrorCollector struct {
	snapshot *Snapshot
	severity *lsp.DiagnosticSeverity
	source   *string
	shadowed map[string]struct{}
	builtins map[string]struct{}
	result   []lsp.Diagnostic
}

// liveBuiltinNames is the set of names the registry actually defines. A
// contract in the metadata table for a name no longer registered would
// otherwise let this rule report a call to something that does not exist.
func liveBuiltinNames() map[string]struct{} {
	names := make(map[string]struct{}, len(builtin.Builtins))
	for _, def := range builtin.Builtins {
		if def.Name != "" {
			names[def.Name] = struct{}{}
		}
	}
	return names
}

// errorBinding is one `let value, err = f(...)` whose f is a builtin declaring
// the (value, err) contract.
//
// value is carried alongside err because for one family of builtins reading it
// *is* reading the error -- see flagIsRead.
type errorBinding struct {
	callee    string
	name      *mast.Identifier
	offset    int
	value     *mast.Identifier
	valueFlag bool
}

// checkScope examines one function body -- or the top level -- and then each
// function literal written inside it as a scope of its own.
//
// The scope is the function rather than the block, because that is what the
// compiler does: an `if` or `for` body shares the enclosing function's
// bindings, so a `let err` inside an `if` replaces the one outside it.
func (c *uncheckedErrorCollector) checkScope(statements []mast.Statement) {
	bindings := c.errorBindings(statements)
	if len(bindings) > 0 {
		rebound := c.bindingOffsetsByName(statements)
		read := c.readOffsetsByName(statements)
		tested := c.conditionOffsetsByName(statements)
		captured := namesUsedInsideNestedFunctions(statements)

		for _, binding := range bindings {
			c.report(binding, rebound, read, tested, captured)
		}
	}

	for _, nested := range nestedFunctionBodies(statements) {
		c.checkScope(nested)
	}
}

// errorBindings finds the `let`s in this scope that bind the error half of a
// pair-returning builtin call.
//
// Every guard here is one the two shipped return-contract rules already use:
// the callee must be a plain identifier, unshadowed, a live builtin, and carry
// a declared contract. A builtin with no declared return contract is never
// reported -- that is what has kept this family of rules free of false
// positives as coverage grew, and it is not weakened here.
func (c *uncheckedErrorCollector) errorBindings(statements []mast.Statement) []errorBinding {
	var found []errorBinding

	forEachStatementInScope(statements, func(stmt mast.Statement) {
		let, ok := stmt.(*mast.LetStatement)
		if !ok || let.Value == nil {
			return
		}
		call, ok := let.Value.(*mast.CallExpression)
		if !ok {
			return
		}
		calleeName, _, ok := builtinCallee(call.Function, func(name string) bool {
			_, shadowed := c.shadowed[name]
			return shadowed
		})
		if !ok {
			return
		}
		if _, live := c.builtins[calleeName]; !live {
			return
		}
		spec, declared := builtin.ReturnSpec(calleeName)
		if !declared || !spec.Pair {
			return
		}

		// One name against a pair is builtinPairReturn's report, not this
		// one: there is no error binding to be unread, because the name
		// holds the whole MULTI_VALUE.
		names := letNames(let)
		if len(names) < 2 {
			return
		}
		errorName := names[1]
		if errorName == nil || errorName.Value == "" {
			return
		}
		// `_` is how the language says "I know this can fail and I am
		// choosing not to look". Reporting it would leave no way to say that.
		if errorName.Value == "_" {
			return
		}

		rng, ok := c.snapshot.Program.RangeOf(errorName)
		if !ok {
			return
		}

		found = append(found, errorBinding{
			callee:    calleeName,
			name:      errorName,
			offset:    rng.Start.Offset,
			value:     names[0],
			valueFlag: len(spec.Kinds) == 1 && spec.Kinds[0] == builtin.ParamBool,
		})
	})

	return found
}

// bindingOffsetsByName records where every name in this scope is bound. It is
// what ends a binding's window: the next `let` of the same name is the point
// after which a read is reading something else.
func (c *uncheckedErrorCollector) bindingOffsetsByName(statements []mast.Statement) map[string][]int {
	offsets := make(map[string][]int)

	forEachStatementInScope(statements, func(stmt mast.Statement) {
		let, ok := stmt.(*mast.LetStatement)
		if !ok {
			return
		}
		for _, name := range letNames(let) {
			if name == nil || name.Value == "" {
				continue
			}
			if rng, ok := c.snapshot.Program.RangeOf(name); ok {
				offsets[name.Value] = append(offsets[name.Value], rng.Start.Offset)
			}
		}
	})

	return offsets
}

// readOffsetsByName records where every name is read in this scope, function
// literals excluded -- those are handled separately, because a closure's
// position in the file says nothing about when it runs.
//
// A `let`'s own names are not reads and do not appear here: the shared walker
// descends into a LetStatement's value and not into the names it binds.
func (c *uncheckedErrorCollector) readOffsetsByName(statements []mast.Statement) map[string][]int {
	offsets := make(map[string][]int)

	forEachStatementInScope(statements, func(stmt mast.Statement) {
		walkExpressions(stmt, false, func(expr mast.Expression) {
			ident, ok := expr.(*mast.Identifier)
			if !ok || ident == nil || ident.Value == "" {
				return
			}
			if rng, ok := c.snapshot.Program.RangeOf(ident); ok {
				offsets[ident.Value] = append(offsets[ident.Value], rng.Start.Offset)
			}
		})
	})

	return offsets
}

// namesUsedInsideNestedFunctions collects every name mentioned inside a
// function literal written in this scope.
//
// Such a mention is excused without asking where it sits, because a closure
// runs when it is called and not where it is written: a handler defined above
// the binding still reads it, and one defined below may read it long after the
// name has been rebound. The set is also not scope-accurate -- a nested body's
// own `err` lands in it too -- which over-excuses rather than over-reports, and
// that is the direction this rule errs in everywhere.
func namesUsedInsideNestedFunctions(statements []mast.Statement) map[string]struct{} {
	used := make(map[string]struct{})
	for _, body := range nestedFunctionBodies(statements) {
		for _, stmt := range body {
			visitExpressions(stmt, func(expr mast.Expression) {
				if ident, ok := expr.(*mast.Identifier); ok && ident != nil && ident.Value != "" {
					used[ident.Value] = struct{}{}
				}
			})
		}
	}
	return used
}

func (c *uncheckedErrorCollector) report(
	binding errorBinding,
	rebound map[string][]int,
	read map[string][]int,
	tested map[string][]int,
	captured map[string]struct{},
) {
	if _, taken := captured[binding.name.Value]; taken {
		return
	}

	limit := nextOffsetAfter(rebound[binding.name.Value], binding.offset)
	for _, at := range read[binding.name.Value] {
		if at > binding.offset && at < limit {
			return
		}
	}

	// The failure may have been caught through the value instead. Both ways
	// of doing that rest on the same fact: a pair-returning builtin leaves
	// null -- or false -- in the value it could not produce.
	if c.failureSeenThroughValue(binding, rebound, read, tested, captured) {
		return
	}

	rng, ok := c.snapshot.Program.RangeOf(binding.name)
	if !ok {
		return
	}

	c.result = append(c.result, lsp.Diagnostic{
		Range:    localprotocol.ToLSPRange(rng),
		Severity: c.severity,
		Source:   c.source,
		Message: fmt.Sprintf(
			"`%s` can fail, and this `%s` is never read before it is rebound or the scope ends. A failed call leaves nothing usable in the value beside it -- null, or false where the value is a success flag -- so the program carries on with that and reports success. Test it (`if (%s) { ... }`), pass it on, or bind `_` to say the failure is deliberately ignored.",
			binding.callee, binding.name.Value, binding.name.Value),
	})
}

// nextOffsetAfter returns the smallest offset greater than after, or a value
// past the end of any file when there is none -- a binding that is never
// replaced is live to the end of its scope.
func nextOffsetAfter(offsets []int, after int) int {
	limit := math.MaxInt
	for _, offset := range offsets {
		if offset > after && offset < limit {
			limit = offset
		}
	}
	return limit
}

// flagIsRead reports whether the program branched on the failure through the
// success value instead of through the error.
//
// It applies to one family, identified from the contract rather than by name:
// a builtin whose success value is a bare BOOLEAN returns false on every
// failure path, so `if (!ok)` and `if (ok)` are complete failure checks. Six
// fs_write calls in the corpus are written exactly that way, and reporting them
// would be telling a program that correctly handles failure that it ignores it.
//
// The narrower complaint that survives -- that a false from fs_exists cannot be
// told apart from a broken one -- is a different rule, and a much fuzzier one.
// This rule reports a failure nothing acts on, and that is not this.
//
// A non-BOOLEAN value earns no such reading: json_stringify hands back null on
// failure, and a program that goes on to write that null has not checked
// anything.
func (c *uncheckedErrorCollector) failureSeenThroughValue(
	binding errorBinding,
	rebound map[string][]int,
	read map[string][]int,
	tested map[string][]int,
	captured map[string]struct{},
) bool {
	if binding.value == nil || binding.value.Value == "" || binding.value.Value == "_" {
		return false
	}
	if _, taken := captured[binding.value.Value]; taken {
		return true
	}

	rng, ok := c.snapshot.Program.RangeOf(binding.value)
	if !ok {
		return false
	}
	limit := nextOffsetAfter(rebound[binding.value.Value], rng.Start.Offset)

	// A value written into an `if` or `for` condition is one the program
	// branches on, and on failure it is null -- so the failure changes which
	// branch runs. `if (req) { path = req["path"]; }` guards the whole use.
	for _, at := range tested[binding.value.Value] {
		if at > rng.Start.Offset && at < limit {
			return true
		}
	}

	// A BOOLEAN success value needs no condition around it: it is false on
	// every failure path, so returning it, passing it on, or combining it
	// carries the failure wherever it goes. Six fs_write calls in the corpus
	// are written that way, and reporting them would tell a program that
	// handles failure correctly that it ignores it.
	//
	// No other kind earns this reading. json_stringify hands back null, and a
	// program that writes that null to a file has checked nothing.
	if !binding.valueFlag {
		return false
	}
	for _, at := range read[binding.value.Value] {
		if at > rng.Start.Offset && at < limit {
			return true
		}
	}
	return false
}

// conditionOffsetsByName records where each name is read inside an `if` or
// `for` condition -- the only two places this language branches. A name there
// decides which code runs, which is what makes reading it a check rather than
// a use.
func (c *uncheckedErrorCollector) conditionOffsetsByName(statements []mast.Statement) map[string][]int {
	offsets := make(map[string][]int)

	collect := func(condition mast.Expression) {
		if condition == nil {
			return
		}
		visitExpressions(condition, func(expr mast.Expression) {
			ident, ok := expr.(*mast.Identifier)
			if !ok || ident == nil || ident.Value == "" {
				return
			}
			if rng, ok := c.snapshot.Program.RangeOf(ident); ok {
				offsets[ident.Value] = append(offsets[ident.Value], rng.Start.Offset)
			}
		})
	}

	forEachStatementInScope(statements, func(stmt mast.Statement) {
		if loop, ok := stmt.(*mast.ForStatement); ok && loop != nil {
			collect(loop.Condition)
		}
		walkExpressions(stmt, false, func(expr mast.Expression) {
			if ifExpr, ok := expr.(*mast.IfExpression); ok && ifExpr != nil {
				collect(ifExpr.Condition)
			}
		})
	})

	return offsets
}
