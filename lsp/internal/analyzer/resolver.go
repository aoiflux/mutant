package analyzer

import (
	mast "mutant/ast"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

type binding struct {
	ident *mast.Identifier
	rng   mast.Range
	kind  lsp.CompletionItemKind
}

type scope struct {
	parent *scope
	defs   map[string]binding
}

func newScope(parent *scope) *scope {
	return &scope{parent: parent, defs: make(map[string]binding)}
}

func (s *scope) define(name string, ident *mast.Identifier, rng mast.Range, kind lsp.CompletionItemKind) {
	if s == nil || ident == nil || name == "" || !rng.IsValid() {
		return
	}
	s.defs[name] = binding{ident: ident, rng: rng, kind: kind}
}

func (s *scope) resolve(name string) (binding, bool) {
	for current := s; current != nil; current = current.parent {
		if b, ok := current.defs[name]; ok {
			return b, true
		}
	}
	return binding{}, false
}

func (s *Snapshot) DefinitionLocation(uri lsp.DocumentUri, pos lsp.Position) (*lsp.Location, bool) {
	if s == nil || s.Program == nil {
		return nil, false
	}

	binding, ok := s.resolveDefinition(pos)
	if !ok {
		return nil, false
	}

	location := &lsp.Location{
		URI:   uri,
		Range: localprotocol.ToLSPRange(binding.rng),
	}
	return location, true
}

func (s *Snapshot) ReferenceLocations(uri lsp.DocumentUri, pos lsp.Position, includeDeclaration bool) ([]lsp.Location, bool) {
	if s == nil || s.Program == nil {
		return nil, false
	}

	target, ok := s.resolveDefinition(pos)
	if !ok {
		return nil, false
	}

	collector := referenceCollector{
		snapshot:           s,
		uri:                uri,
		target:             target,
		includeDeclaration: includeDeclaration,
		seen:               make(map[mast.Range]struct{}),
		locations:          make([]lsp.Location, 0, 4),
	}
	root := newScope(nil)
	for _, stmt := range s.Program.Statements {
		collector.collectStatement(stmt, root)
	}
	if len(collector.locations) == 0 {
		return nil, false
	}
	return collector.locations, true
}

func (s *Snapshot) resolveDefinition(pos lsp.Position) (binding, bool) {
	root := newScope(nil)
	for _, stmt := range s.Program.Statements {
		if resolved, ok := s.resolveStatement(stmt, root, pos); ok {
			return resolved, true
		}
	}
	return binding{}, false
}

func (s *Snapshot) resolveStatement(stmt mast.Statement, current *scope, pos lsp.Position) (binding, bool) {
	switch node := stmt.(type) {
	case *mast.LetStatement:
		names := node.Names
		if len(names) == 0 && node.Name != nil {
			names = []*mast.Identifier{node.Name}
		}

		if len(names) == 1 {
			if rng, ok := s.identifierRange(names[0]); ok {
				current.define(names[0].Value, names[0], rng, kindForLetValue(node.Value))
				if localprotocol.ContainsPosition(rng, pos) {
					return binding{ident: names[0], rng: rng, kind: kindForLetValue(node.Value)}, true
				}
			}
		} else {
			for _, name := range names {
				if rng, ok := s.identifierRange(name); ok && localprotocol.ContainsPosition(rng, pos) {
					return binding{ident: name, rng: rng, kind: lsp.CompletionItemKindVariable}, true
				}
			}
		}

		if node.Value != nil {
			if resolved, ok := s.resolveExpression(node.Value, current, pos); ok {
				return resolved, true
			}
		}

		if len(names) > 1 {
			for _, name := range names {
				if rng, ok := s.identifierRange(name); ok {
					current.define(name.Value, name, rng, lsp.CompletionItemKindVariable)
				}
			}
		}
	case *mast.ReturnStatement:
		for _, expr := range node.ReturnValues {
			if resolved, ok := s.resolveExpression(expr, current, pos); ok {
				return resolved, true
			}
		}
		if len(node.ReturnValues) == 0 && node.ReturnValue != nil {
			if resolved, ok := s.resolveExpression(node.ReturnValue, current, pos); ok {
				return resolved, true
			}
		}
	case *mast.ExpressionStatement:
		if node.Expression != nil {
			return s.resolveExpression(node.Expression, current, pos)
		}
	case *mast.BlockStatement:
		for _, inner := range node.Statements {
			if resolved, ok := s.resolveStatement(inner, current, pos); ok {
				return resolved, true
			}
		}
	case *mast.ForStatement:
		if node.Init != nil {
			if resolved, ok := s.resolveStatement(node.Init, current, pos); ok {
				return resolved, true
			}
		}
		if node.Condition != nil {
			if resolved, ok := s.resolveExpression(node.Condition, current, pos); ok {
				return resolved, true
			}
		}
		if node.Post != nil {
			if resolved, ok := s.resolveExpression(node.Post, current, pos); ok {
				return resolved, true
			}
		}
		if node.Body != nil {
			if resolved, ok := s.resolveStatement(node.Body, current, pos); ok {
				return resolved, true
			}
		}
	case *mast.StructStatement:
		if rng, ok := s.identifierRange(node.Name); ok {
			current.define(node.Name.Value, node.Name, rng, lsp.CompletionItemKindStruct)
			if localprotocol.ContainsPosition(rng, pos) {
				return binding{ident: node.Name, rng: rng, kind: lsp.CompletionItemKindStruct}, true
			}
		}
		for _, field := range node.Fields {
			if rng, ok := s.identifierRange(field); ok && localprotocol.ContainsPosition(rng, pos) {
				return binding{ident: field, rng: rng, kind: lsp.CompletionItemKindField}, true
			}
		}
	case *mast.EnumStatement:
		if rng, ok := s.identifierRange(node.Name); ok {
			current.define(node.Name.Value, node.Name, rng, lsp.CompletionItemKindEnum)
			if localprotocol.ContainsPosition(rng, pos) {
				return binding{ident: node.Name, rng: rng, kind: lsp.CompletionItemKindEnum}, true
			}
		}
		for _, variant := range node.Variants {
			if rng, ok := s.identifierRange(variant); ok && localprotocol.ContainsPosition(rng, pos) {
				return binding{ident: variant, rng: rng, kind: lsp.CompletionItemKindEnumMember}, true
			}
		}
	}

	return binding{}, false
}

func (s *Snapshot) resolveExpression(expr mast.Expression, current *scope, pos lsp.Position) (binding, bool) {
	switch node := expr.(type) {
	case *mast.Identifier:
		rng, ok := s.identifierRange(node)
		if !ok || !localprotocol.ContainsPosition(rng, pos) {
			return binding{}, false
		}
		resolved, ok := current.resolve(node.Value)
		if !ok {
			return binding{}, false
		}
		return resolved, true
	case *mast.FunctionLiteral:
		child := newScope(current)
		for _, param := range node.Parameters {
			if rng, ok := s.identifierRange(param); ok {
				child.define(param.Value, param, rng, lsp.CompletionItemKindVariable)
				if localprotocol.ContainsPosition(rng, pos) {
					return binding{ident: param, rng: rng, kind: lsp.CompletionItemKindVariable}, true
				}
			}
		}
		if node.Body != nil {
			return s.resolveStatement(node.Body, child, pos)
		}
	case *mast.IfExpression:
		if node.Condition != nil {
			if resolved, ok := s.resolveExpression(node.Condition, current, pos); ok {
				return resolved, true
			}
		}
		if node.Consequence != nil {
			if resolved, ok := s.resolveStatement(node.Consequence, current, pos); ok {
				return resolved, true
			}
		}
		if node.Alternative != nil {
			if resolved, ok := s.resolveStatement(node.Alternative, current, pos); ok {
				return resolved, true
			}
		}
	case *mast.CallExpression:
		if node.Function != nil {
			if resolved, ok := s.resolveExpression(node.Function, current, pos); ok {
				return resolved, true
			}
		}
		for _, arg := range node.Arguments {
			if resolved, ok := s.resolveExpression(arg, current, pos); ok {
				return resolved, true
			}
		}
	case *mast.PrefixExpression:
		if node.Right != nil {
			return s.resolveExpression(node.Right, current, pos)
		}
	case *mast.InfixExpression:
		if node.Left != nil {
			if resolved, ok := s.resolveExpression(node.Left, current, pos); ok {
				return resolved, true
			}
		}
		if node.Right != nil {
			if resolved, ok := s.resolveExpression(node.Right, current, pos); ok {
				return resolved, true
			}
		}
	case *mast.IndexExpression:
		if node.Left != nil {
			if resolved, ok := s.resolveExpression(node.Left, current, pos); ok {
				return resolved, true
			}
		}
		if node.Index != nil {
			if resolved, ok := s.resolveExpression(node.Index, current, pos); ok {
				return resolved, true
			}
		}
	case *mast.AssignExpression:
		if node.Left != nil {
			if resolved, ok := s.resolveExpression(node.Left, current, pos); ok {
				return resolved, true
			}
		}
		if node.Value != nil {
			if resolved, ok := s.resolveExpression(node.Value, current, pos); ok {
				return resolved, true
			}
		}
	case *mast.FieldExpression:
		if node.Left != nil {
			if resolved, ok := s.resolveExpression(node.Left, current, pos); ok {
				return resolved, true
			}
		}
		if rng, ok := s.identifierRange(node.Field); ok && localprotocol.ContainsPosition(rng, pos) {
			if enumType, ok := s.resolveEnumTypeBinding(node.Left, current); ok {
				if variant, ok := s.enumVariantBinding(enumType.ident.Value, node.Field.Value); ok {
					return variant, true
				}
			}
			if structType, ok := s.resolveStructTypeName(node.Left, current); ok {
				if field, ok := s.structFieldBinding(structType, node.Field.Value); ok {
					return field, true
				}
			}
			return binding{ident: node.Field, rng: rng, kind: lsp.CompletionItemKindField}, true
		}
	case *mast.StructLiteral:
		if node.Name != nil {
			if resolved, ok := s.resolveExpression(node.Name, current, pos); ok {
				return resolved, true
			}
		}
		for _, field := range node.Fields {
			if field == nil {
				continue
			}
			if rng, ok := s.identifierRange(field.Name); ok && localprotocol.ContainsPosition(rng, pos) {
				if node.Name != nil {
					if resolvedField, ok := s.structFieldBinding(node.Name.Value, field.Name.Value); ok {
						return resolvedField, true
					}
				}
				return binding{ident: field.Name, rng: rng, kind: lsp.CompletionItemKindField}, true
			}
			if field.Value != nil {
				if resolved, ok := s.resolveExpression(field.Value, current, pos); ok {
					return resolved, true
				}
			}
		}
	case *mast.ArrayLiteral:
		for _, element := range node.Elements {
			if resolved, ok := s.resolveExpression(element, current, pos); ok {
				return resolved, true
			}
		}
	case *mast.HashLiteral:
		for key, value := range node.Pairs {
			if resolved, ok := s.resolveExpression(key, current, pos); ok {
				return resolved, true
			}
			if resolved, ok := s.resolveExpression(value, current, pos); ok {
				return resolved, true
			}
		}
	case *mast.MacroLiteral:
		child := newScope(current)
		for _, param := range node.Parameters {
			if rng, ok := s.identifierRange(param); ok {
				child.define(param.Value, param, rng, lsp.CompletionItemKindVariable)
				if localprotocol.ContainsPosition(rng, pos) {
					return binding{ident: param, rng: rng, kind: lsp.CompletionItemKindVariable}, true
				}
			}
		}
		if node.Body != nil {
			return s.resolveStatement(node.Body, child, pos)
		}
	}

	return binding{}, false
}

func (s *Snapshot) identifierRange(ident *mast.Identifier) (mast.Range, bool) {
	if ident == nil || s == nil || s.Program == nil {
		return mast.Range{}, false
	}
	return s.Program.RangeOf(ident)
}

func (s *Snapshot) resolveEnumTypeBinding(expr mast.Expression, current *scope) (binding, bool) {
	ident, ok := expr.(*mast.Identifier)
	if !ok || ident == nil {
		return binding{}, false
	}
	resolved, ok := current.resolve(ident.Value)
	if !ok || resolved.kind != lsp.CompletionItemKindEnum {
		return binding{}, false
	}
	return resolved, true
}

func (s *Snapshot) enumVariantBinding(enumName, variantName string) (binding, bool) {
	if s == nil || s.Program == nil || enumName == "" || variantName == "" {
		return binding{}, false
	}
	for _, stmt := range s.Program.Statements {
		enumStmt, ok := stmt.(*mast.EnumStatement)
		if !ok || enumStmt.Name == nil || enumStmt.Name.Value != enumName {
			continue
		}
		for _, variant := range enumStmt.Variants {
			if variant == nil || variant.Value != variantName {
				continue
			}
			rng, ok := s.identifierRange(variant)
			if !ok {
				return binding{}, false
			}
			return binding{ident: variant, rng: rng, kind: lsp.CompletionItemKindEnumMember}, true
		}
	}
	return binding{}, false
}

func (s *Snapshot) resolveStructTypeName(expr mast.Expression, current *scope) (string, bool) {
	ident, ok := expr.(*mast.Identifier)
	if !ok || ident == nil {
		return "", false
	}
	resolved, ok := current.resolve(ident.Value)
	if !ok {
		return "", false
	}
	typeName, ok := s.structTypeNameForBinding(resolved)
	if !ok {
		return "", false
	}
	return typeName, true
}

func (s *Snapshot) structTypeNameForBinding(target binding) (string, bool) {
	if s == nil || s.Program == nil || target.ident == nil {
		return "", false
	}
	for _, stmt := range s.Program.Statements {
		if typeName, ok := s.structTypeNameInStatement(stmt, target.ident); ok {
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

func (s *Snapshot) VisibleBindingsAt(pos lsp.Position) []binding {
	if s == nil || s.Program == nil {
		return nil
	}

	current := newScope(nil)
	current = s.scopeAtProgram(current, pos)
	visible := make(map[string]binding)
	for scope := current; scope != nil; scope = scope.parent {
		for name, bind := range scope.defs {
			if _, exists := visible[name]; !exists {
				visible[name] = bind
			}
		}
	}

	bindings := make([]binding, 0, len(visible))
	for _, bind := range visible {
		bindings = append(bindings, bind)
	}
	return bindings
}

func (s *Snapshot) scopeAtProgram(current *scope, pos lsp.Position) *scope {
	for _, stmt := range s.Program.Statements {
		rng, ok := s.Program.RangeOf(stmt)
		if ok && positionBeforeRange(pos, rng) {
			return current
		}
		if ok && localprotocol.ContainsPosition(rng, pos) {
			return s.scopeAtStatement(stmt, current, pos)
		}
		s.advanceStatement(stmt, current)
	}
	return current
}

func (s *Snapshot) scopeAtStatement(stmt mast.Statement, current *scope, pos lsp.Position) *scope {
	switch node := stmt.(type) {
	case *mast.LetStatement:
		names := node.Names
		if len(names) == 0 && node.Name != nil {
			names = []*mast.Identifier{node.Name}
		}
		if len(names) == 1 {
			if rng, ok := s.identifierRange(names[0]); ok {
				current.define(names[0].Value, names[0], rng, kindForLetValue(node.Value))
			}
		}
		if node.Value != nil {
			if child, ok := s.scopeAtExpression(node.Value, current, pos); ok {
				return child
			}
		}
		if len(names) > 1 {
			for _, name := range names {
				if rng, ok := s.identifierRange(name); ok {
					current.define(name.Value, name, rng, lsp.CompletionItemKindVariable)
				}
			}
		}
		return current
	case *mast.ReturnStatement:
		for _, expr := range node.ReturnValues {
			if child, ok := s.scopeAtExpression(expr, current, pos); ok {
				return child
			}
		}
		if len(node.ReturnValues) == 0 && node.ReturnValue != nil {
			if child, ok := s.scopeAtExpression(node.ReturnValue, current, pos); ok {
				return child
			}
		}
		return current
	case *mast.ExpressionStatement:
		if node.Expression != nil {
			if child, ok := s.scopeAtExpression(node.Expression, current, pos); ok {
				return child
			}
		}
		return current
	case *mast.BlockStatement:
		for _, inner := range node.Statements {
			rng, ok := s.Program.RangeOf(inner)
			if ok && positionBeforeRange(pos, rng) {
				return current
			}
			if ok && localprotocol.ContainsPosition(rng, pos) {
				return s.scopeAtStatement(inner, current, pos)
			}
			s.advanceStatement(inner, current)
		}
		return current
	case *mast.ForStatement:
		if node.Init != nil {
			if rng, ok := s.Program.RangeOf(node.Init); ok && localprotocol.ContainsPosition(rng, pos) {
				return s.scopeAtStatement(node.Init, current, pos)
			}
			s.advanceStatement(node.Init, current)
		}
		if node.Condition != nil {
			if child, ok := s.scopeAtExpression(node.Condition, current, pos); ok {
				return child
			}
		}
		if node.Post != nil {
			if child, ok := s.scopeAtExpression(node.Post, current, pos); ok {
				return child
			}
		}
		if node.Body != nil {
			return s.scopeAtStatement(node.Body, current, pos)
		}
		return current
	case *mast.StructStatement:
		if rng, ok := s.identifierRange(node.Name); ok {
			current.define(node.Name.Value, node.Name, rng, lsp.CompletionItemKindStruct)
		}
		return current
	case *mast.EnumStatement:
		if rng, ok := s.identifierRange(node.Name); ok {
			current.define(node.Name.Value, node.Name, rng, lsp.CompletionItemKindEnum)
		}
		return current
	default:
		return current
	}
}

func (s *Snapshot) scopeAtExpression(expr mast.Expression, current *scope, pos lsp.Position) (*scope, bool) {
	rng, ok := s.Program.RangeOf(expr)
	if !ok || !localprotocol.ContainsPosition(rng, pos) {
		return nil, false
	}

	switch node := expr.(type) {
	case *mast.FunctionLiteral:
		child := newScope(current)
		for _, param := range node.Parameters {
			if rng, ok := s.identifierRange(param); ok {
				child.define(param.Value, param, rng, lsp.CompletionItemKindVariable)
			}
		}
		if node.Body != nil {
			return s.scopeAtStatement(node.Body, child, pos), true
		}
		return child, true
	case *mast.MacroLiteral:
		child := newScope(current)
		for _, param := range node.Parameters {
			if rng, ok := s.identifierRange(param); ok {
				child.define(param.Value, param, rng, lsp.CompletionItemKindVariable)
			}
		}
		if node.Body != nil {
			return s.scopeAtStatement(node.Body, child, pos), true
		}
		return child, true
	case *mast.IfExpression:
		if node.Condition != nil {
			if child, ok := s.scopeAtExpression(node.Condition, current, pos); ok {
				return child, true
			}
		}
		if node.Consequence != nil {
			return s.scopeAtStatement(node.Consequence, current, pos), true
		}
		if node.Alternative != nil {
			return s.scopeAtStatement(node.Alternative, current, pos), true
		}
		return current, true
	case *mast.CallExpression:
		if node.Function != nil {
			if child, ok := s.scopeAtExpression(node.Function, current, pos); ok {
				return child, true
			}
		}
		for _, arg := range node.Arguments {
			if child, ok := s.scopeAtExpression(arg, current, pos); ok {
				return child, true
			}
		}
	case *mast.PrefixExpression:
		if node.Right != nil {
			return s.scopeAtExpression(node.Right, current, pos)
		}
	case *mast.InfixExpression:
		if node.Left != nil {
			if child, ok := s.scopeAtExpression(node.Left, current, pos); ok {
				return child, true
			}
		}
		if node.Right != nil {
			if child, ok := s.scopeAtExpression(node.Right, current, pos); ok {
				return child, true
			}
		}
	case *mast.IndexExpression:
		if node.Left != nil {
			if child, ok := s.scopeAtExpression(node.Left, current, pos); ok {
				return child, true
			}
		}
		if node.Index != nil {
			if child, ok := s.scopeAtExpression(node.Index, current, pos); ok {
				return child, true
			}
		}
	case *mast.AssignExpression:
		if node.Left != nil {
			if child, ok := s.scopeAtExpression(node.Left, current, pos); ok {
				return child, true
			}
		}
		if node.Value != nil {
			if child, ok := s.scopeAtExpression(node.Value, current, pos); ok {
				return child, true
			}
		}
	case *mast.FieldExpression:
		if node.Left != nil {
			if child, ok := s.scopeAtExpression(node.Left, current, pos); ok {
				return child, true
			}
		}
		return current, true
	case *mast.StructLiteral:
		if node.Name != nil {
			if child, ok := s.scopeAtExpression(node.Name, current, pos); ok {
				return child, true
			}
		}
		for _, field := range node.Fields {
			if field == nil {
				continue
			}
			if field.Value != nil {
				if child, ok := s.scopeAtExpression(field.Value, current, pos); ok {
					return child, true
				}
			}
		}
	case *mast.ArrayLiteral:
		for _, element := range node.Elements {
			if child, ok := s.scopeAtExpression(element, current, pos); ok {
				return child, true
			}
		}
	case *mast.HashLiteral:
		for key, value := range node.Pairs {
			if child, ok := s.scopeAtExpression(key, current, pos); ok {
				return child, true
			}
			if child, ok := s.scopeAtExpression(value, current, pos); ok {
				return child, true
			}
		}
	}

	return current, true
}

func (s *Snapshot) advanceStatement(stmt mast.Statement, current *scope) {
	switch node := stmt.(type) {
	case *mast.LetStatement:
		names := node.Names
		if len(names) == 0 && node.Name != nil {
			names = []*mast.Identifier{node.Name}
		}
		if len(names) == 1 {
			if rng, ok := s.identifierRange(names[0]); ok {
				current.define(names[0].Value, names[0], rng, kindForLetValue(node.Value))
			}
		}
		if node.Value != nil {
			s.advanceExpression(node.Value, current)
		}
		if len(names) > 1 {
			for _, name := range names {
				if rng, ok := s.identifierRange(name); ok {
					current.define(name.Value, name, rng, lsp.CompletionItemKindVariable)
				}
			}
		}
	case *mast.ReturnStatement:
		for _, expr := range node.ReturnValues {
			s.advanceExpression(expr, current)
		}
		if len(node.ReturnValues) == 0 && node.ReturnValue != nil {
			s.advanceExpression(node.ReturnValue, current)
		}
	case *mast.ExpressionStatement:
		if node.Expression != nil {
			s.advanceExpression(node.Expression, current)
		}
	case *mast.BlockStatement:
		for _, inner := range node.Statements {
			s.advanceStatement(inner, current)
		}
	case *mast.ForStatement:
		if node.Init != nil {
			s.advanceStatement(node.Init, current)
		}
		if node.Condition != nil {
			s.advanceExpression(node.Condition, current)
		}
		if node.Post != nil {
			s.advanceExpression(node.Post, current)
		}
		if node.Body != nil {
			s.advanceStatement(node.Body, current)
		}
	case *mast.StructStatement:
		if rng, ok := s.identifierRange(node.Name); ok {
			current.define(node.Name.Value, node.Name, rng, lsp.CompletionItemKindStruct)
		}
	case *mast.EnumStatement:
		if rng, ok := s.identifierRange(node.Name); ok {
			current.define(node.Name.Value, node.Name, rng, lsp.CompletionItemKindEnum)
		}
	}
}

func (s *Snapshot) advanceExpression(expr mast.Expression, current *scope) {
	switch node := expr.(type) {
	case *mast.FunctionLiteral, *mast.MacroLiteral:
		return
	case *mast.IfExpression:
		if node.Condition != nil {
			s.advanceExpression(node.Condition, current)
		}
		if node.Consequence != nil {
			s.advanceStatement(node.Consequence, current)
		}
		if node.Alternative != nil {
			s.advanceStatement(node.Alternative, current)
		}
	case *mast.CallExpression:
		if node.Function != nil {
			s.advanceExpression(node.Function, current)
		}
		for _, arg := range node.Arguments {
			s.advanceExpression(arg, current)
		}
	case *mast.PrefixExpression:
		if node.Right != nil {
			s.advanceExpression(node.Right, current)
		}
	case *mast.InfixExpression:
		if node.Left != nil {
			s.advanceExpression(node.Left, current)
		}
		if node.Right != nil {
			s.advanceExpression(node.Right, current)
		}
	case *mast.IndexExpression:
		if node.Left != nil {
			s.advanceExpression(node.Left, current)
		}
		if node.Index != nil {
			s.advanceExpression(node.Index, current)
		}
	case *mast.AssignExpression:
		if node.Left != nil {
			s.advanceExpression(node.Left, current)
		}
		if node.Value != nil {
			s.advanceExpression(node.Value, current)
		}
	case *mast.FieldExpression:
		if node.Left != nil {
			s.advanceExpression(node.Left, current)
		}
	case *mast.StructLiteral:
		if node.Name != nil {
			s.advanceExpression(node.Name, current)
		}
		for _, field := range node.Fields {
			if field != nil && field.Value != nil {
				s.advanceExpression(field.Value, current)
			}
		}
	case *mast.ArrayLiteral:
		for _, element := range node.Elements {
			s.advanceExpression(element, current)
		}
	case *mast.HashLiteral:
		for key, value := range node.Pairs {
			s.advanceExpression(key, current)
			s.advanceExpression(value, current)
		}
	}
}

func kindForLetValue(value mast.Expression) lsp.CompletionItemKind {
	if _, ok := value.(*mast.FunctionLiteral); ok {
		return lsp.CompletionItemKindFunction
	}
	return lsp.CompletionItemKindVariable
}

func positionBeforeRange(pos lsp.Position, rng mast.Range) bool {
	line := int(pos.Line) + 1
	col := int(pos.Character) + 1
	if line != rng.Start.Line {
		return line < rng.Start.Line
	}
	return col < rng.Start.Column
}

type referenceCollector struct {
	snapshot           *Snapshot
	uri                lsp.DocumentUri
	target             binding
	includeDeclaration bool
	seen               map[mast.Range]struct{}
	locations          []lsp.Location
}

func (c *referenceCollector) collectStatement(stmt mast.Statement, current *scope) {
	switch node := stmt.(type) {
	case *mast.LetStatement:
		names := node.Names
		if len(names) == 0 && node.Name != nil {
			names = []*mast.Identifier{node.Name}
		}

		if len(names) == 1 {
			if rng, ok := c.snapshot.identifierRange(names[0]); ok {
				defined := binding{ident: names[0], rng: rng, kind: kindForLetValue(node.Value)}
				current.define(names[0].Value, names[0], rng, defined.kind)
				c.addOccurrenceIfTarget(defined, rng, true)
			}
		}

		if node.Value != nil {
			c.collectExpression(node.Value, current)
		}

		if len(names) > 1 {
			for _, name := range names {
				if rng, ok := c.snapshot.identifierRange(name); ok {
					defined := binding{ident: name, rng: rng, kind: lsp.CompletionItemKindVariable}
					current.define(name.Value, name, rng, defined.kind)
					c.addOccurrenceIfTarget(defined, rng, true)
				}
			}
		}
	case *mast.ReturnStatement:
		for _, expr := range node.ReturnValues {
			c.collectExpression(expr, current)
		}
		if len(node.ReturnValues) == 0 && node.ReturnValue != nil {
			c.collectExpression(node.ReturnValue, current)
		}
	case *mast.ExpressionStatement:
		if node.Expression != nil {
			c.collectExpression(node.Expression, current)
		}
	case *mast.BlockStatement:
		for _, inner := range node.Statements {
			c.collectStatement(inner, current)
		}
	case *mast.ForStatement:
		if node.Init != nil {
			c.collectStatement(node.Init, current)
		}
		if node.Condition != nil {
			c.collectExpression(node.Condition, current)
		}
		if node.Post != nil {
			c.collectExpression(node.Post, current)
		}
		if node.Body != nil {
			c.collectStatement(node.Body, current)
		}
	case *mast.StructStatement:
		if rng, ok := c.snapshot.identifierRange(node.Name); ok {
			defined := binding{ident: node.Name, rng: rng, kind: lsp.CompletionItemKindStruct}
			current.define(node.Name.Value, node.Name, rng, defined.kind)
			c.addOccurrenceIfTarget(defined, rng, true)
		}
		for _, field := range node.Fields {
			if field == nil {
				continue
			}
			if rng, ok := c.snapshot.identifierRange(field); ok {
				declared := binding{ident: field, rng: rng, kind: lsp.CompletionItemKindField}
				c.addOccurrenceIfTarget(declared, rng, true)
			}
		}
	case *mast.EnumStatement:
		if rng, ok := c.snapshot.identifierRange(node.Name); ok {
			defined := binding{ident: node.Name, rng: rng, kind: lsp.CompletionItemKindEnum}
			current.define(node.Name.Value, node.Name, rng, defined.kind)
			c.addOccurrenceIfTarget(defined, rng, true)
		}
		for _, variant := range node.Variants {
			if variant == nil {
				continue
			}
			if rng, ok := c.snapshot.identifierRange(variant); ok {
				declared := binding{ident: variant, rng: rng, kind: lsp.CompletionItemKindEnumMember}
				c.addOccurrenceIfTarget(declared, rng, true)
			}
		}
	}
}

func (c *referenceCollector) collectExpression(expr mast.Expression, current *scope) {
	switch node := expr.(type) {
	case *mast.Identifier:
		rng, ok := c.snapshot.identifierRange(node)
		if !ok {
			return
		}
		resolved, ok := current.resolve(node.Value)
		if !ok {
			return
		}
		c.addOccurrenceIfTarget(resolved, rng, false)
	case *mast.FunctionLiteral:
		child := newScope(current)
		for _, param := range node.Parameters {
			if rng, ok := c.snapshot.identifierRange(param); ok {
				defined := binding{ident: param, rng: rng, kind: lsp.CompletionItemKindVariable}
				child.define(param.Value, param, rng, defined.kind)
				c.addOccurrenceIfTarget(defined, rng, true)
			}
		}
		if node.Body != nil {
			c.collectStatement(node.Body, child)
		}
	case *mast.IfExpression:
		if node.Condition != nil {
			c.collectExpression(node.Condition, current)
		}
		if node.Consequence != nil {
			c.collectStatement(node.Consequence, current)
		}
		if node.Alternative != nil {
			c.collectStatement(node.Alternative, current)
		}
	case *mast.CallExpression:
		if node.Function != nil {
			c.collectExpression(node.Function, current)
		}
		for _, arg := range node.Arguments {
			c.collectExpression(arg, current)
		}
	case *mast.PrefixExpression:
		if node.Right != nil {
			c.collectExpression(node.Right, current)
		}
	case *mast.InfixExpression:
		if node.Left != nil {
			c.collectExpression(node.Left, current)
		}
		if node.Right != nil {
			c.collectExpression(node.Right, current)
		}
	case *mast.IndexExpression:
		if node.Left != nil {
			c.collectExpression(node.Left, current)
		}
		if node.Index != nil {
			c.collectExpression(node.Index, current)
		}
	case *mast.AssignExpression:
		if node.Left != nil {
			c.collectExpression(node.Left, current)
		}
		if node.Value != nil {
			c.collectExpression(node.Value, current)
		}
	case *mast.FieldExpression:
		if node.Left != nil {
			c.collectExpression(node.Left, current)
		}
		if rng, ok := c.snapshot.identifierRange(node.Field); ok {
			if enumType, ok := c.snapshot.resolveEnumTypeBinding(node.Left, current); ok {
				if variant, ok := c.snapshot.enumVariantBinding(enumType.ident.Value, node.Field.Value); ok {
					c.addOccurrenceIfTarget(variant, rng, false)
				}
			}
			if structType, ok := c.snapshot.resolveStructTypeName(node.Left, current); ok {
				if field, ok := c.snapshot.structFieldBinding(structType, node.Field.Value); ok {
					c.addOccurrenceIfTarget(field, rng, false)
				}
			}
		}
	case *mast.StructLiteral:
		if node.Name != nil {
			c.collectExpression(node.Name, current)
		}
		for _, field := range node.Fields {
			if field == nil {
				continue
			}
			if node.Name != nil {
				if rng, ok := c.snapshot.identifierRange(field.Name); ok {
					if declared, ok := c.snapshot.structFieldBinding(node.Name.Value, field.Name.Value); ok {
						c.addOccurrenceIfTarget(declared, rng, false)
					}
				}
			}
			if field.Value != nil {
				c.collectExpression(field.Value, current)
			}
		}
	case *mast.ArrayLiteral:
		for _, element := range node.Elements {
			c.collectExpression(element, current)
		}
	case *mast.HashLiteral:
		for key, value := range node.Pairs {
			c.collectExpression(key, current)
			c.collectExpression(value, current)
		}
	case *mast.MacroLiteral:
		child := newScope(current)
		for _, param := range node.Parameters {
			if rng, ok := c.snapshot.identifierRange(param); ok {
				defined := binding{ident: param, rng: rng, kind: lsp.CompletionItemKindVariable}
				child.define(param.Value, param, rng, defined.kind)
				c.addOccurrenceIfTarget(defined, rng, true)
			}
		}
		if node.Body != nil {
			c.collectStatement(node.Body, child)
		}
	}
}

func (c *referenceCollector) addOccurrenceIfTarget(resolved binding, occurrence mast.Range, declaration bool) {
	if !sameBinding(resolved, c.target) {
		return
	}
	if declaration && !c.includeDeclaration {
		return
	}
	if !occurrence.IsValid() {
		return
	}
	if _, ok := c.seen[occurrence]; ok {
		return
	}
	c.seen[occurrence] = struct{}{}
	c.locations = append(c.locations, lsp.Location{
		URI:   c.uri,
		Range: localprotocol.ToLSPRange(occurrence),
	})
}

func sameBinding(left, right binding) bool {
	if !left.rng.IsValid() || !right.rng.IsValid() {
		return false
	}
	return left.rng == right.rng
}
