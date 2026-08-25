package analyzer

// A spawned closure -- and a pmap or peach callback -- runs on its own VM with a
// *snapshot* of the globals. It reads the values that existed when the call was
// made, and its own writes go to that copy and are gone when the worker
// finishes. Ordinary closures do not behave this way: a plain `fn` writing a
// global writes the one shared globals slice, so the same line means two
// different things depending on who runs it.
//
// The snapshot is a deliberate decision, documented in MUTANT_LANGUAGE_REFERENCE
// -- share-nothing is what makes concurrent VMs safe over one compiled program.
// What it did not have was a diagnostic. The program compiles, runs, reports
// nothing and quietly does not do what it says, which is the same profile as
// binding two names from a single-return builtin: the reason that one was worth
// a rule is the reason this one is.
//
// The rule is deliberately narrow. A false positive here tells someone their
// correct code is wrong, so it declines wherever it cannot be certain:
//
//   - Only a function literal written at the call site is examined. A callback
//     passed by name can also be called directly somewhere else, where the very
//     same write does take effect.
//   - Only a name declared at the top level counts. A captured local is copied by
//     every closure, spawned or not, so a write to one is not specific to this.
//   - A name rebound anywhere inside the callback -- by a parameter or a `let` --
//     is a different variable, and is left alone.

import (
	"fmt"

	mast "mutant/ast"
	"mutant/builtin"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// spawnGlobalWriteCallbackArg maps each builtin that runs a callback on a worker
// VM to the argument its callback arrives in.
//
// net_serve is deliberately absent: it takes a handler *file path*, not a
// closure, so there is no callback body here to look inside.
var spawnGlobalWriteCallbackArg = map[string]int{
	builtin.BuiltinNameSpawn: 0,
	builtin.BuiltinNamePMap:  1,
	builtin.BuiltinNamePEach: 1,
}

func lintSpawnGlobalWrites(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}

	severity, ok := lintConfig.severityForRule("spawnGlobalWrite")
	if !ok {
		return nil
	}

	globals := topLevelLetNames(snapshot.Program.Statements)
	if len(globals) == 0 {
		return nil
	}

	source := "mutant-lint"
	collector := &spawnWriteCollector{
		snapshot: snapshot,
		severity: severity,
		source:   &source,
		globals:  globals,
	}

	for _, stmt := range snapshot.Program.Statements {
		collector.findCallbacks(stmt)
	}

	return collector.result
}

type spawnWriteCollector struct {
	snapshot *Snapshot
	severity *lsp.DiagnosticSeverity
	source   *string
	globals  map[string]struct{}
	result   []lsp.Diagnostic
}

// findCallbacks walks the program for spawn/pmap/peach calls whose callback is
// written inline, and reports the global writes inside each one.
func (c *spawnWriteCollector) findCallbacks(node mast.Node) {
	visitExpressions(node, func(expr mast.Expression) {
		call, ok := expr.(*mast.CallExpression)
		if !ok {
			return
		}
		callee, ok := call.Function.(*mast.Identifier)
		if !ok || callee == nil {
			return
		}
		position, watched := spawnGlobalWriteCallbackArg[callee.Value]
		if !watched || position >= len(call.Arguments) {
			return
		}
		literal, ok := call.Arguments[position].(*mast.FunctionLiteral)
		if !ok || literal == nil {
			return
		}

		c.reportWrites(literal, callee.Value, shadowedNames(literal, nil))
	})
}

// reportWrites walks one callback body. shadowed holds every name this closure
// binds for itself, so a write to one of those is a write to a local.
func (c *spawnWriteCollector) reportWrites(literal *mast.FunctionLiteral, builtinName string, shadowed map[string]struct{}) {
	if literal == nil || literal.Body == nil {
		return
	}

	// Shallow: a nested function inside the callback runs on the same worker VM,
	// so its writes are lost the same way -- but it may rebind the name, so it
	// gets its own recursive walk with its own bindings. Letting the walker
	// descend as well would visit that body twice, once with the wrong set.
	walkExpressions(literal.Body, false, func(expr mast.Expression) {
		if nested, ok := expr.(*mast.FunctionLiteral); ok && nested != literal {
			c.reportWrites(nested, builtinName, shadowedNames(nested, shadowed))
			return
		}

		assign, ok := expr.(*mast.AssignExpression)
		if !ok {
			return
		}
		target := assignmentRoot(assign.Left)
		if target == nil || target.Value == "" || target.Value == "_" {
			return
		}
		if _, isGlobal := c.globals[target.Value]; !isGlobal {
			return
		}
		if _, rebound := shadowed[target.Value]; rebound {
			return
		}

		rng, ok := c.snapshot.Program.RangeOf(target)
		if !ok {
			return
		}

		c.result = append(c.result, lsp.Diagnostic{
			Range:    localprotocol.ToLSPRange(rng),
			Severity: c.severity,
			Source:   c.source,
			Message: fmt.Sprintf(
				"`%s` is a global, and %s runs this callback with its own copy of the globals, so this write is lost when the callback finishes. Return the value, or send it through a channel.",
				target.Value, builtinName),
		})
	})
}

// visitExpressions calls visit on every expression reachable from node,
// nested function literals included.
func visitExpressions(node mast.Node, visit func(mast.Expression)) {
	walkExpressions(node, true, visit)
}

// walkExpressions is visitExpressions with the descent into nested function
// literals made optional. A caller that walks a function body under a set of
// bindings needs enterFunctions=false: a nested body has different bindings, so
// it has to be walked separately rather than as part of this one.
func walkExpressions(node mast.Node, enterFunctions bool, visit func(mast.Expression)) {
	var walkStatement func(mast.Statement)
	var walkExpression func(mast.Expression)

	walkExpression = func(e mast.Expression) {
		if e == nil {
			return
		}
		visit(e)

		switch n := e.(type) {
		case *mast.CallExpression:
			walkExpression(n.Function)
			for _, arg := range n.Arguments {
				walkExpression(arg)
			}
		case *mast.FunctionLiteral:
			if enterFunctions && n.Body != nil {
				walkStatement(n.Body)
			}
		case *mast.InfixExpression:
			walkExpression(n.Left)
			walkExpression(n.Right)
		case *mast.PrefixExpression:
			walkExpression(n.Right)
		case *mast.IndexExpression:
			walkExpression(n.Left)
			walkExpression(n.Index)
		case *mast.AssignExpression:
			walkExpression(n.Left)
			walkExpression(n.Value)
		case *mast.FieldExpression:
			walkExpression(n.Left)
		case *mast.ArrayLiteral:
			for _, el := range n.Elements {
				walkExpression(el)
			}
		case *mast.HashLiteral:
			for key, value := range n.Pairs {
				walkExpression(key)
				walkExpression(value)
			}
		case *mast.StructLiteral:
			for _, field := range n.Fields {
				if field != nil {
					walkExpression(field.Value)
				}
			}
		case *mast.IfExpression:
			walkExpression(n.Condition)
			if n.Consequence != nil {
				walkStatement(n.Consequence)
			}
			if n.Alternative != nil {
				walkStatement(n.Alternative)
			}
		}
	}

	walkStatement = func(s mast.Statement) {
		switch n := s.(type) {
		case *mast.LetStatement:
			walkExpression(n.Value)
		case *mast.ExpressionStatement:
			walkExpression(n.Expression)
		case *mast.ReturnStatement:
			for _, value := range n.ReturnValues {
				walkExpression(value)
			}
			walkExpression(n.ReturnValue)
		case *mast.BlockStatement:
			for _, inner := range n.Statements {
				walkStatement(inner)
			}
		case *mast.ForStatement:
			if n.Init != nil {
				walkStatement(n.Init)
			}
			walkExpression(n.Condition)
			walkExpression(n.Post)
			if n.Body != nil {
				walkStatement(n.Body)
			}
		}
	}

	switch n := node.(type) {
	case mast.Statement:
		walkStatement(n)
	case mast.Expression:
		walkExpression(n)
	}
}

// shadowedNames returns every name a function literal binds for itself: its
// parameters, plus every `let` in its body outside a nested function.
//
// The whole body is one set rather than a stack of block scopes, because that is
// what the compiler does -- an `if` or `for` body shares the enclosing function's
// scope -- and because when in doubt this rule would rather stay quiet.
func shadowedNames(literal *mast.FunctionLiteral, inherited map[string]struct{}) map[string]struct{} {
	names := make(map[string]struct{}, len(inherited)+len(literal.Parameters)+2)
	for name := range inherited {
		names[name] = struct{}{}
	}
	for _, param := range literal.Parameters {
		if param != nil && param.Value != "" {
			names[param.Value] = struct{}{}
		}
	}
	collectLetNames(literal.Body, names)
	return names
}

// collectLetNames adds every name bound by a `let` in this body, without
// descending into a nested function literal, whose bindings belong to it.
func collectLetNames(stmt mast.Statement, into map[string]struct{}) {
	switch n := stmt.(type) {
	case nil:
		return
	case *mast.LetStatement:
		for _, ident := range letNames(n) {
			if ident != nil && ident.Value != "" {
				into[ident.Value] = struct{}{}
			}
		}
	case *mast.BlockStatement:
		for _, inner := range n.Statements {
			collectLetNames(inner, into)
		}
	case *mast.ForStatement:
		collectLetNames(n.Init, into)
		collectLetNames(n.Body, into)
	case *mast.ExpressionStatement:
		if ifExpr, ok := n.Expression.(*mast.IfExpression); ok {
			collectLetNames(ifExpr.Consequence, into)
			collectLetNames(ifExpr.Alternative, into)
		}
	}
}

func letNames(stmt *mast.LetStatement) []*mast.Identifier {
	if stmt == nil {
		return nil
	}
	if len(stmt.Names) > 0 {
		return stmt.Names
	}
	if stmt.Name != nil {
		return []*mast.Identifier{stmt.Name}
	}
	return nil
}

// topLevelLetNames collects the program's globals: every name a top-level `let`
// binds, including a top-level for-loop's own counter, which shares that scope.
func topLevelLetNames(statements []mast.Statement) map[string]struct{} {
	names := make(map[string]struct{}, len(statements))
	for _, stmt := range statements {
		switch n := stmt.(type) {
		case *mast.LetStatement:
			for _, ident := range letNames(n) {
				if ident != nil && ident.Value != "" && ident.Value != "_" {
					names[ident.Value] = struct{}{}
				}
			}
		case *mast.ForStatement:
			if init, ok := n.Init.(*mast.LetStatement); ok {
				for _, ident := range letNames(init) {
					if ident != nil && ident.Value != "" && ident.Value != "_" {
						names[ident.Value] = struct{}{}
					}
				}
			}
		}
	}
	return names
}

// assignmentRoot finds the variable an assignment ultimately stores back into.
// `x = v` is x; so are `x[i] = v` and `x.field = v`, because indexed and field
// stores write the container back to its own slot -- which for a global in a
// worker means back into the worker's copy.
func assignmentRoot(target mast.Expression) *mast.Identifier {
	for {
		switch n := target.(type) {
		case *mast.Identifier:
			return n
		case *mast.IndexExpression:
			target = n.Left
		case *mast.FieldExpression:
			target = n.Left
		default:
			return nil
		}
	}
}
