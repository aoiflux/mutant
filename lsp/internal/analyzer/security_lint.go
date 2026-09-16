package analyzer

// Shared ground for the security rules of T-2.
//
// The four contract rules that shipped before these -- builtinSingleReturn,
// builtinPairReturn, unclosedResource, uncheckedError -- are right by
// construction: each reads a fact the registry declares about a builtin and
// compares it with what the call site wrote. The security rules read *intent*,
// and intent has to be inferred, so each one needs its own answer to "what
// makes this certain enough to squiggle?".
//
// What they share is the plumbing below: how to walk a scope, how to see
// through one hop of `let`, and how to read a literal. Nothing here decides
// anything. The decisions live in the rule files.

import (
	mast "mutant/ast"
)

// forEachScope visits the statements of the top level and then of every
// function literal written anywhere inside it, each as a scope of its own.
//
// It is the recursion every rule in this family opens with, lifted out of the
// four copies it would otherwise be. A scope rather than the file, because the
// function is what the compiler treats as a unit: an `if` or `for` body shares
// the enclosing function's bindings, so a `let` inside one replaces the name
// outside it, while a `let` inside a nested function does not.
func forEachScope(statements []mast.Statement, visit func(scope []mast.Statement)) {
	if len(statements) == 0 {
		return
	}
	visit(statements)
	for _, nested := range nestedFunctionBodies(statements) {
		forEachScope(nested, visit)
	}
}

// singleBindings maps each name this scope binds exactly once to the
// expression it was bound to.
//
// A name bound twice is absent: with two values in play, "the value of x" has
// no answer a rule may rely on without tracking where the reader sits, and a
// rule that guesses wrong reports correct code. Absent is the quiet direction
// for every caller here -- a rule that cannot resolve a name says nothing.
//
// One hop is the whole depth on purpose. The corpus writes
//
//	let tls_opts = {"server_name": host, "min_version": "1.2"};
//	net_tls_connect(host, timeout, tls_opts);
//
// and a rule that only read an inline literal would miss the idiom the
// language's own examples teach. Two hops is where a linter starts guessing.
func singleBindings(statements []mast.Statement) map[string]mast.Expression {
	values := make(map[string]mast.Expression)
	rebound := make(map[string]struct{})

	forEachStatementInScope(statements, func(stmt mast.Statement) {
		let, ok := stmt.(*mast.LetStatement)
		if !ok {
			return
		}
		names := letNames(let)
		if len(names) == 0 || names[0] == nil || names[0].Value == "" || names[0].Value == "_" {
			for _, name := range names {
				if name != nil && name.Value != "" {
					rebound[name.Value] = struct{}{}
				}
			}
			return
		}
		// `let value, err = f(...)` is how this language calls anything that
		// can fail, so the first name of a multi-name `let` is recorded: it
		// holds the call's value. The names beside it hold the error and are
		// not the value expression, so they are treated as bound to nothing.
		//
		// Recording the call rather than the value half is deliberately loose
		// and costs nothing, because every reader of this map either wants a
		// literal -- and a call is never one -- or wants the call itself.
		for _, name := range names[1:] {
			if name != nil && name.Value != "" {
				rebound[name.Value] = struct{}{}
			}
		}
		name := names[0].Value
		if _, seen := values[name]; seen {
			rebound[name] = struct{}{}
			return
		}
		if let.Value == nil {
			rebound[name] = struct{}{}
			return
		}
		values[name] = let.Value
	})

	// An assignment is a second value for the name just as a second `let` is.
	for _, stmt := range statements {
		walkExpressions(stmt, false, func(expr mast.Expression) {
			assign, ok := expr.(*mast.AssignExpression)
			if !ok || assign == nil {
				return
			}
			if ident, ok := assign.Left.(*mast.Identifier); ok && ident != nil {
				rebound[ident.Value] = struct{}{}
			}
		})
	}

	for name := range rebound {
		delete(values, name)
	}
	return values
}

// resolveOneHop returns the expression an argument stands for: itself, or --
// when it is a bare name this scope binds exactly once -- the expression it was
// bound to.
func resolveOneHop(expr mast.Expression, bindings map[string]mast.Expression) mast.Expression {
	ident, ok := expr.(*mast.Identifier)
	if !ok || ident == nil || ident.Value == "" {
		return expr
	}
	if bound, found := bindings[ident.Value]; found && bound != nil {
		return bound
	}
	return expr
}

// literalString reads a string literal. A TemplateLiteral is deliberately not
// one: it holds expressions, so its value is not known here.
func literalString(expr mast.Expression) (string, bool) {
	str, ok := expr.(*mast.StringLiteral)
	if !ok || str == nil {
		return "", false
	}
	return str.Value, true
}

// literalBool reads a boolean literal.
func literalBool(expr mast.Expression) (bool, bool) {
	value, ok := expr.(*mast.Boolean)
	if !ok || value == nil {
		return false, false
	}
	return value.Value, true
}

// literalInt reads an integer literal, negation included -- `-1` parses as a
// prefix expression over a literal, and a rule that could not read it would be
// silent on exactly the argument most likely to be wrong.
func literalInt(expr mast.Expression) (int64, bool) {
	switch node := expr.(type) {
	case *mast.IntegerLiteral:
		if node == nil {
			return 0, false
		}
		return node.Value, true
	case *mast.PrefixExpression:
		if node == nil || node.Operator != "-" {
			return 0, false
		}
		inner, ok := literalInt(node.Right)
		if !ok {
			return 0, false
		}
		return -inner, true
	}
	return 0, false
}

// literalEntry reads one named entry out of a hash or struct literal.
//
// Both spellings are accepted because both reach the same option decoder: the
// TLS builtins document `options?` as "Hash or struct", and `optBool` does not
// care which the author wrote.
//
// A hash key is matched only when it is itself a string literal. A computed key
// is a key this cannot know.
func literalEntry(expr mast.Expression, key string) (mast.Expression, bool) {
	switch node := expr.(type) {
	case *mast.HashLiteral:
		if node == nil {
			return nil, false
		}
		for name, value := range node.Pairs {
			if text, ok := literalString(name); ok && text == key {
				return value, true
			}
		}
	case *mast.StructLiteral:
		if node == nil {
			return nil, false
		}
		for _, field := range node.Fields {
			if field == nil || field.Name == nil || field.Value == nil {
				continue
			}
			if field.Name.Value == key {
				return field.Value, true
			}
		}
	}
	return nil, false
}

// argumentAt returns the call's nth argument, or nil when the call is shorter
// than that. Every builtin with an `options?` tail can be called without it.
func argumentAt(call *mast.CallExpression, index int) mast.Expression {
	if call == nil || index < 0 || index >= len(call.Arguments) {
		return nil
	}
	return call.Arguments[index]
}

// securityCallCollector is the walk each security rule shares: every call in
// one scope whose callee is an unshadowed, live builtin, together with the
// bindings of that scope so an argument can be followed one hop.
//
// Rules that need a call site and nothing else use this. Rules that need to
// relate two statements to each other (evidenceMutation, pathTraversal) walk
// for themselves.
func forEachBuiltinCall(
	statements []mast.Statement,
	shadowed map[string]struct{},
	visit func(name string, anchor mast.Node, call *mast.CallExpression, bindings map[string]mast.Expression),
) {
	live := liveBuiltinNames()
	isShadowed := func(name string) bool {
		_, taken := shadowed[name]
		return taken
	}

	forEachScope(statements, func(scope []mast.Statement) {
		var bindings map[string]mast.Expression

		for _, stmt := range scope {
			walkExpressions(stmt, false, func(expr mast.Expression) {
				call, ok := expr.(*mast.CallExpression)
				if !ok || call == nil {
					return
				}
				name, anchor, ok := builtinCallee(call.Function, isShadowed)
				if !ok {
					return
				}
				if _, exists := live[name]; !exists {
					return
				}
				// Built on first use: most scopes hold no call this family
				// cares about, and walking every `let` in them would be work
				// for nothing.
				if bindings == nil {
					bindings = singleBindings(scope)
				}
				visit(name, anchor, call, bindings)
			})
		}
	})
}
