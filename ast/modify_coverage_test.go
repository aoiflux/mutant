package ast

import (
	"reflect"
	"testing"
)

// Modify is a switch over node types, so a type it has no case for is a silent
// dead end: the walk stops, and whatever the modifier was meant to do to that
// subtree never happens. That is not a theoretical gap. There was no
// *CallExpression case, so macro expansion never reached a macro used as an
// argument, and `putln(emit_literal())` failed to compile with "undefined
// variable: emit_literal" while `let x = emit_literal();` worked.
//
// These tests plant a marker expression inside each node type and assert the
// modifier reached it.

func markerIn(t *testing.T, node Node) bool {
	t.Helper()

	seen := false
	Modify(node, func(n Node) Node {
		if literal, ok := n.(*IntegerLiteral); ok && literal.Value == 1 {
			seen = true
			literal.Value = 2
		}
		return n
	})
	return seen
}

func TestModifyReachesEveryNodeTypeWithChildren(t *testing.T) {
	marker := func() Expression { return &IntegerLiteral{Value: 1} }

	cases := []struct {
		name string
		node Node
	}{
		{"call argument", &CallExpression{
			Function:  &Identifier{Value: "putln"},
			Arguments: []Expression{marker()},
		}},
		{"call callee", &CallExpression{
			Function:  &IndexExpression{Left: &Identifier{Value: "fns"}, Index: marker()},
			Arguments: []Expression{},
		}},
		{"nested call argument", &CallExpression{
			Function: &Identifier{Value: "putln"},
			Arguments: []Expression{&CallExpression{
				Function:  &Identifier{Value: "inner"},
				Arguments: []Expression{marker()},
			}},
		}},
		{"for init", &ForStatement{
			Init: &LetStatement{Name: &Identifier{Value: "i"}, Names: []*Identifier{{Value: "i"}}, Value: marker()},
			Body: &BlockStatement{},
		}},
		{"for condition", &ForStatement{Condition: marker(), Body: &BlockStatement{}}},
		{"for post", &ForStatement{Post: marker(), Body: &BlockStatement{}}},
		{"for body", &ForStatement{Body: &BlockStatement{
			Statements: []Statement{&ExpressionStatement{Expression: marker()}},
		}}},
		{"assignment value", &AssignExpression{Left: &Identifier{Value: "x"}, Value: marker()}},
		{"assignment target", &AssignExpression{
			Left:  &IndexExpression{Left: &Identifier{Value: "a"}, Index: marker()},
			Value: &Identifier{Value: "v"},
		}},
		{"field receiver", &FieldExpression{
			Left:  &IndexExpression{Left: &Identifier{Value: "a"}, Index: marker()},
			Field: &Identifier{Value: "name"},
		}},
		{"struct literal field", &StructLiteral{
			Name:   &Identifier{Value: "Point"},
			Fields: []*StructFieldValue{{Name: &Identifier{Value: "x"}, Value: marker()}},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !markerIn(t, tc.node) {
				t.Fatalf("Modify never reached the expression inside %T", tc.node)
			}
		})
	}
}

// A `for (;;)` has no init, condition or post. Modify must walk it without
// inventing children or panicking on the missing ones.
func TestModifyHandlesEmptyForHeader(t *testing.T) {
	loop := &ForStatement{Body: &BlockStatement{
		Statements: []Statement{&ExpressionStatement{Expression: &IntegerLiteral{Value: 1}}},
	}}

	if !markerIn(t, loop) {
		t.Fatal("Modify did not reach the body of a headerless for")
	}
	if loop.Init != nil || loop.Condition != nil || loop.Post != nil {
		t.Fatalf("Modify populated an absent for-header part: init=%v condition=%v post=%v",
			loop.Init, loop.Condition, loop.Post)
	}
}

// A macro body is a template, expanded per call site in the caller's
// environment. Walking into it here would expand it once, at the definition,
// against the wrong bindings -- so the omission is deliberate and worth pinning
// so it is not "fixed" by someone completing the switch.
func TestModifyDoesNotDescendIntoMacroBodies(t *testing.T) {
	macro := &MacroLiteral{
		Parameters: []*Identifier{{Value: "x"}},
		Body: &BlockStatement{
			Statements: []Statement{&ExpressionStatement{Expression: &IntegerLiteral{Value: 1}}},
		},
	}

	if markerIn(t, macro) {
		t.Fatal("Modify descended into a macro body; expansion must happen at the call site")
	}
}

// The parser keeps LetStatement.Name pointing at Names[0]. Modify rewrites the
// Names slice, so it has to re-establish that rather than leave Name pointing
// at the pre-modification identifier.
func TestModifyKeepsLetNameAliasedToFirstName(t *testing.T) {
	first := &Identifier{Value: "a"}
	stmt := &LetStatement{Name: first, Names: []*Identifier{first, {Value: "err"}}, Value: &IntegerLiteral{Value: 1}}

	Modify(stmt, func(n Node) Node { return n })

	if stmt.Name != stmt.Names[0] {
		t.Fatalf("Name is no longer the same identifier as Names[0]: %p vs %p", stmt.Name, stmt.Names[0])
	}
}

// The bottom-up contract: a node's children are final before the modifier sees
// the node, so a modifier that replaces a call can rely on its arguments having
// already been rewritten.
func TestModifyIsBottomUp(t *testing.T) {
	inner := &CallExpression{Function: &Identifier{Value: "inner"}, Arguments: []Expression{}}
	outer := &CallExpression{Function: &Identifier{Value: "outer"}, Arguments: []Expression{inner}}

	order := []string{}
	Modify(outer, func(n Node) Node {
		if call, ok := n.(*CallExpression); ok {
			if ident, ok := call.Function.(*Identifier); ok {
				order = append(order, ident.Value)
			}
		}
		return n
	})

	want := []string{"inner", "outer"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("modifier visited calls in order %v, want %v", order, want)
	}
}
