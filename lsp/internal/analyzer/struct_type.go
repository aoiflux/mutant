package analyzer

import (
	mast "mutant/ast"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// Which struct a value holds is not a question about names, so it is not a
// question sema.Graph answers. The graph records that `p.x` was written and
// that `p` refers to some declaration; which field `x` names depends on what
// `p` contains, and that is inference.
//
// This is the syntactic half of that inference, kept from the walk this package
// used to do five of: it finds the struct literal a binding was initialised
// from by looking at the statement that declares it. Snapshot.TypeOf reaches
// strictly more -- a struct arriving through a function's return, or through
// another binding -- and type_definition.go already prefers it. This stays
// because two callers still read it directly, and because it answers without
// running the inference pass.

// structTypeNameForDeclaration takes the identifier that DECLARES a binding,
// never a use of it. Handing it a use would mean first asking what the use
// refers to, and that is the question this helps answer.
func (s *Snapshot) structTypeNameForDeclaration(target *mast.Identifier) (string, bool) {
	if s == nil || s.Program == nil || target == nil {
		return "", false
	}
	for _, stmt := range s.Program.Statements {
		if typeName, ok := s.structTypeNameInStatement(stmt, target); ok {
			return typeName, true
		}
	}
	return "", false
}

func (s *Snapshot) structTypeNameInStatement(stmt mast.Statement, target *mast.Identifier) (string, bool) {
	switch node := stmt.(type) {
	case *mast.LetStatement:
		names := node.Names
		if len(names) == 0 && node.Name != nil {
			names = []*mast.Identifier{node.Name}
		}
		for _, name := range names {
			if name != target {
				continue
			}
			literal, ok := node.Value.(*mast.StructLiteral)
			if !ok || literal == nil || literal.Name == nil {
				return "", false
			}
			return literal.Name.Value, true
		}
		if node.Value != nil {
			return s.structTypeNameInExpression(node.Value, target)
		}
	case *mast.ReturnStatement:
		for _, expr := range node.ReturnValues {
			if typeName, ok := s.structTypeNameInExpression(expr, target); ok {
				return typeName, true
			}
		}
		if len(node.ReturnValues) == 0 && node.ReturnValue != nil {
			return s.structTypeNameInExpression(node.ReturnValue, target)
		}
	case *mast.ExpressionStatement:
		if node.Expression != nil {
			return s.structTypeNameInExpression(node.Expression, target)
		}
	case *mast.BlockStatement:
		for _, inner := range node.Statements {
			if typeName, ok := s.structTypeNameInStatement(inner, target); ok {
				return typeName, true
			}
		}
	case *mast.ForInStatement:
		if node.Iterable != nil {
			if typeName, ok := s.structTypeNameInExpression(node.Iterable, target); ok {
				return typeName, true
			}
		}
		if node.Body != nil {
			if typeName, ok := s.structTypeNameInStatement(node.Body, target); ok {
				return typeName, true
			}
		}
	case *mast.WhileStatement:
		if node.Condition != nil {
			if typeName, ok := s.structTypeNameInExpression(node.Condition, target); ok {
				return typeName, true
			}
		}
		if node.Body != nil {
			if typeName, ok := s.structTypeNameInStatement(node.Body, target); ok {
				return typeName, true
			}
		}
	case *mast.ForStatement:
		if node.Init != nil {
			if typeName, ok := s.structTypeNameInStatement(node.Init, target); ok {
				return typeName, true
			}
		}
		if node.Condition != nil {
			if typeName, ok := s.structTypeNameInExpression(node.Condition, target); ok {
				return typeName, true
			}
		}
		if node.Post != nil {
			if typeName, ok := s.structTypeNameInExpression(node.Post, target); ok {
				return typeName, true
			}
		}
		if node.Body != nil {
			return s.structTypeNameInStatement(node.Body, target)
		}
	}
	return "", false
}

func (s *Snapshot) structTypeNameInExpression(expr mast.Expression, target *mast.Identifier) (string, bool) {
	switch node := expr.(type) {
	case *mast.FunctionLiteral:
		if node.Body != nil {
			return s.structTypeNameInStatement(node.Body, target)
		}
	case *mast.IfExpression:
		if node.Condition != nil {
			if typeName, ok := s.structTypeNameInExpression(node.Condition, target); ok {
				return typeName, true
			}
		}
		if node.Consequence != nil {
			if typeName, ok := s.structTypeNameInStatement(node.Consequence, target); ok {
				return typeName, true
			}
		}
		if node.Alternative != nil {
			if typeName, ok := s.structTypeNameInStatement(node.Alternative, target); ok {
				return typeName, true
			}
		}
	case *mast.MatchExpression:
		if node.Subject != nil {
			if typeName, ok := s.structTypeNameInExpression(node.Subject, target); ok {
				return typeName, true
			}
		}
		for _, arm := range node.Arms {
			if arm == nil || arm.Body == nil {
				continue
			}
			if typeName, ok := s.structTypeNameInStatement(arm.Body, target); ok {
				return typeName, true
			}
		}
	case *mast.CallExpression:
		if node.Function != nil {
			if typeName, ok := s.structTypeNameInExpression(node.Function, target); ok {
				return typeName, true
			}
		}
		for _, arg := range node.Arguments {
			if typeName, ok := s.structTypeNameInExpression(arg, target); ok {
				return typeName, true
			}
		}
	case *mast.PrefixExpression:
		if node.Right != nil {
			return s.structTypeNameInExpression(node.Right, target)
		}
	case *mast.InfixExpression:
		if node.Left != nil {
			if typeName, ok := s.structTypeNameInExpression(node.Left, target); ok {
				return typeName, true
			}
		}
		if node.Right != nil {
			if typeName, ok := s.structTypeNameInExpression(node.Right, target); ok {
				return typeName, true
			}
		}
	case *mast.IndexExpression:
		if node.Left != nil {
			if typeName, ok := s.structTypeNameInExpression(node.Left, target); ok {
				return typeName, true
			}
		}
		if node.Index != nil {
			if typeName, ok := s.structTypeNameInExpression(node.Index, target); ok {
				return typeName, true
			}
		}
	case *mast.AssignExpression:
		if node.Left != nil {
			if typeName, ok := s.structTypeNameInExpression(node.Left, target); ok {
				return typeName, true
			}
		}
		if node.Value != nil {
			if typeName, ok := s.structTypeNameInExpression(node.Value, target); ok {
				return typeName, true
			}
		}
	case *mast.FieldExpression:
		if node.Left != nil {
			return s.structTypeNameInExpression(node.Left, target)
		}
	case *mast.StructLiteral:
		if node.Name != nil {
			if typeName, ok := s.structTypeNameInExpression(node.Name, target); ok {
				return typeName, true
			}
		}
		for _, field := range node.Fields {
			if field != nil && field.Value != nil {
				if typeName, ok := s.structTypeNameInExpression(field.Value, target); ok {
					return typeName, true
				}
			}
		}
	case *mast.ArrayLiteral:
		for _, element := range node.Elements {
			if typeName, ok := s.structTypeNameInExpression(element, target); ok {
				return typeName, true
			}
		}
	case *mast.TemplateLiteral:
		for _, element := range node.Parts {
			if typeName, ok := s.structTypeNameInExpression(element, target); ok {
				return typeName, true
			}
		}
	case *mast.HashLiteral:
		for key, value := range node.Pairs {
			if typeName, ok := s.structTypeNameInExpression(key, target); ok {
				return typeName, true
			}
			if typeName, ok := s.structTypeNameInExpression(value, target); ok {
				return typeName, true
			}
		}
	case *mast.MacroLiteral:
		if node.Body != nil {
			return s.structTypeNameInStatement(node.Body, target)
		}
	}
	return "", false
}

func (s *Snapshot) structFieldBinding(structName, fieldName string) (binding, bool) {
	if s == nil || s.Program == nil || structName == "" || fieldName == "" {
		return binding{}, false
	}
	for _, stmt := range s.Program.Statements {
		structStmt, ok := stmt.(*mast.StructStatement)
		if !ok || structStmt.Name == nil || structStmt.Name.Value != structName {
			continue
		}
		for _, field := range structStmt.Fields {
			if field == nil || field.Value != fieldName {
				continue
			}
			rng, ok := s.identifierRange(field)
			if !ok {
				return binding{}, false
			}
			return binding{ident: field, rng: rng, kind: lsp.CompletionItemKindField}, true
		}
	}
	return binding{}, false
}
