package evaluator

import (
	"fmt"
	"mutant/ast"
	"mutant/object"
	"mutant/token"
)

// quote captures an AST node as a value, with any unquote(...) inside it
// replaced by what that expression evaluates to.
//
// The node is copied first. evalUnquoteCalls rewrites in place, and the node it
// is handed belongs to whatever produced it -- for a macro, that is the macro's
// own body, which is a template every call re-uses. Substituting into the
// original meant the first expansion's arguments were baked in permanently, so
// add_expr(3, 9) followed by add_expr(x, 5) both evaluated to 12.
func quote(node ast.Node, env *object.Environment) object.Object {
	quoted, err := evalUnquoteCalls(ast.Clone(node), env)
	if err != nil {
		return err
	}
	return &object.Quote{Node: quoted}
}

// evalUnquoteCalls replaces every unquote(...) with the source form of what it
// evaluates to. A value with no source form is an error rather than a silent
// nil: a nil in the tree compiles to a call with a missing argument, and the VM
// then dies with "index out of range [-1]" a whole phase away from the cause.
func evalUnquoteCalls(quoted ast.Node, env *object.Environment) (ast.Node, *object.Error) {
	var failure *object.Error

	modified := ast.Modify(quoted, func(node ast.Node) ast.Node {
		if failure != nil || !isUnquoteCall(node) {
			return node
		}

		call, ok := node.(*ast.CallExpression)
		if !ok {
			return node
		}

		if len(call.Arguments) != 1 {
			failure = newError("unquote takes exactly one expression, got %d", len(call.Arguments))
			return node
		}

		unquoted := Eval(call.Arguments[0], env)
		if isError(unquoted) {
			failure, _ = unquoted.(*object.Error)
			return node
		}

		converted, err := convertObjectToASTNode(unquoted)
		if err != nil {
			failure = err
			return node
		}
		return converted
	})

	if failure != nil {
		return nil, failure
	}
	return modified, nil
}

func isUnquoteCall(node ast.Node) bool {
	callExpression, ok := node.(*ast.CallExpression)
	if !ok {
		return false
	}

	return callExpression.Function.TokenLiteral() == "unquote"
}

// convertObjectToASTNode turns a runtime value back into the source that would
// produce it. Only values with a literal spelling can make that trip -- an
// array, a hash, a function or a null has no literal the compiler could read
// back, so it is reported instead of being dropped.
func convertObjectToASTNode(obj object.Object) (ast.Node, *object.Error) {
	switch obj := obj.(type) {
	case *object.Integer:
		t := token.Token{
			Type:    token.INT,
			Literal: fmt.Sprintf("%d", obj.Value),
		}
		return &ast.IntegerLiteral{Token: t, Value: obj.Value}, nil
	case *object.Float:
		t := token.Token{
			Type:    token.FLOAT,
			Literal: fmt.Sprintf("%g", obj.Value),
		}
		return &ast.FloatLiteral{Token: t, Value: obj.Value}, nil
	case *object.String:
		// The literal is what the tree prints, so it carries the quotes the
		// source form needs; Value is what the compiler reads.
		t := token.Token{
			Type:    token.STRING,
			Literal: fmt.Sprintf("%q", obj.Value),
		}
		return &ast.StringLiteral{Token: t, Value: obj.Value}, nil
	case *object.Boolean:
		var t token.Token
		if obj.Value {
			t = token.Token{Type: token.TRUE, Literal: "true"}
		} else {
			t = token.Token{Type: token.FALSE, Literal: "false"}
		}
		return &ast.Boolean{Token: t, Value: obj.Value}, nil
	case *object.Quote:
		return obj.Node, nil
	case nil:
		return nil, newError("unquote: expression produced nothing")
	default:
		return nil, newError("unquote: %s has no source form", obj.Type())
	}
}
