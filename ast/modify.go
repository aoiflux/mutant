package ast

type ModifierFunc func(Node) Node

// Modify rewrites a tree bottom-up: every child is modified before the node
// that holds it, so a modifier that replaces a node sees children that are
// already final.
//
// Every node type that can hold an expression has to have a case here. A
// missing one is silent -- the walk simply stops there and the modifier never
// sees the subtree. That is how `putln(emit_literal())` used to fail to
// compile: there was no *CallExpression case, so macro expansion never reached
// a macro call that appeared as an argument, and the call survived to codegen
// as an undefined variable.
func Modify(node Node, modifier ModifierFunc) Node {
	switch node := node.(type) {
	case *Program:
		for i, stmt := range node.Statements {
			node.Statements[i], _ = Modify(stmt, modifier).(Statement)
		}
	case *ExpressionStatement:
		node.Expression, _ = Modify(node.Expression, modifier).(Expression)
	case *InfixExpression:
		node.Left, _ = Modify(node.Left, modifier).(Expression)
		node.Right, _ = Modify(node.Right, modifier).(Expression)
	case *PrefixExpression:
		node.Right, _ = Modify(node.Right, modifier).(Expression)
	case *IndexExpression:
		node.Left, _ = Modify(node.Left, modifier).(Expression)
		node.Index, _ = Modify(node.Index, modifier).(Expression)
	case *CallExpression:
		// The callee is modified too: it may be an expression rather than a bare
		// name (`fns[0](x)`, `obj.method(x)`).
		if node.Function != nil {
			node.Function, _ = Modify(node.Function, modifier).(Expression)
		}
		for i := range node.Arguments {
			if node.Arguments[i] == nil {
				continue
			}
			node.Arguments[i], _ = Modify(node.Arguments[i], modifier).(Expression)
		}
	case *IfExpression:
		node.Condition, _ = Modify(node.Condition, modifier).(Expression)
		node.Consequence, _ = Modify(node.Consequence, modifier).(*BlockStatement)
		if node.Alternative != nil {
			node.Alternative, _ = Modify(node.Alternative, modifier).(*BlockStatement)
		}
	case *BlockStatement:
		for i := range node.Statements {
			node.Statements[i], _ = Modify(node.Statements[i], modifier).(Statement)
		}
	case *ForStatement:
		// Every part of the header is optional -- `for (;;)` has none of them.
		if node.Init != nil {
			node.Init, _ = Modify(node.Init, modifier).(Statement)
		}
		if node.Condition != nil {
			node.Condition, _ = Modify(node.Condition, modifier).(Expression)
		}
		if node.Post != nil {
			node.Post, _ = Modify(node.Post, modifier).(Expression)
		}
		if node.Body != nil {
			node.Body, _ = Modify(node.Body, modifier).(*BlockStatement)
		}
	case *ReturnStatement:
		if len(node.ReturnValues) > 0 {
			for i := range node.ReturnValues {
				node.ReturnValues[i], _ = Modify(node.ReturnValues[i], modifier).(Expression)
			}
			node.ReturnValue = node.ReturnValues[0]
		} else {
			node.ReturnValue, _ = Modify(node.ReturnValue, modifier).(Expression)
		}
	case *LetStatement:
		for i := range node.Names {
			node.Names[i], _ = Modify(node.Names[i], modifier).(*Identifier)
		}
		if len(node.Names) > 0 {
			node.Name = node.Names[0]
		}
		node.Value, _ = Modify(node.Value, modifier).(Expression)
	case *AssignExpression:
		if node.Left != nil {
			node.Left, _ = Modify(node.Left, modifier).(Expression)
		}
		if node.Value != nil {
			node.Value, _ = Modify(node.Value, modifier).(Expression)
		}
	case *FieldExpression:
		if node.Left != nil {
			node.Left, _ = Modify(node.Left, modifier).(Expression)
		}
		if node.Field != nil {
			node.Field, _ = Modify(node.Field, modifier).(*Identifier)
		}
	case *FunctionLiteral:
		for i := range node.Parameters {
			node.Parameters[i], _ = Modify(node.Parameters[i], modifier).(*Identifier)
		}
		node.Body, _ = Modify(node.Body, modifier).(*BlockStatement)
	case *ArrayLiteral:
		for i := range node.Elements {
			node.Elements[i], _ = Modify(node.Elements[i], modifier).(Expression)
		}
	case *HashLiteral:
		newPairs := make(map[Expression]Expression)
		for key, val := range node.Pairs {
			newKey, _ := Modify(key, modifier).(Expression)
			newVal, _ := Modify(val, modifier).(Expression)
			newPairs[newKey] = newVal
		}
		node.Pairs = newPairs
	case *StructLiteral:
		if node.Name != nil {
			node.Name, _ = Modify(node.Name, modifier).(*Identifier)
		}
		for _, field := range node.Fields {
			if field == nil {
				continue
			}
			if field.Name != nil {
				field.Name, _ = Modify(field.Name, modifier).(*Identifier)
			}
			if field.Value != nil {
				field.Value, _ = Modify(field.Value, modifier).(Expression)
			}
		}
	case *StructStatement:
		if node.Name != nil {
			node.Name, _ = Modify(node.Name, modifier).(*Identifier)
		}
		for i := range node.Fields {
			node.Fields[i], _ = Modify(node.Fields[i], modifier).(*Identifier)
		}
	case *EnumStatement:
		if node.Name != nil {
			node.Name, _ = Modify(node.Name, modifier).(*Identifier)
		}
		for i := range node.Variants {
			node.Variants[i], _ = Modify(node.Variants[i], modifier).(*Identifier)
		}
	}

	// Deliberately no *MacroLiteral case. A macro body is a template, expanded
	// when the macro is called and in the call's environment; walking into it
	// here would expand it once, at its definition site, against the wrong
	// bindings.

	return modifier(node)
}
