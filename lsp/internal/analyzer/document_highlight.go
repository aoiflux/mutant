package analyzer

import (
	mast "mutant/ast"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func (s *Snapshot) DocumentHighlights(uri lsp.DocumentUri, pos lsp.Position) ([]lsp.DocumentHighlight, bool) {
	if s == nil || s.Program == nil {
		return nil, false
	}

	resolved, ok := s.resolveDefinition(pos)
	if !ok || resolved.ident == nil {
		return nil, false
	}

	locations, ok := s.ReferenceLocations(uri, pos, true)
	if !ok || len(locations) == 0 {
		return nil, false
	}

	writeRanges := s.assignmentWriteRanges(resolved.ident.Value)
	highlights := make([]lsp.DocumentHighlight, 0, len(locations))
	for _, location := range locations {
		kind := lsp.DocumentHighlightKindRead
		if location.Range == localprotocol.ToLSPRange(resolved.rng) || writeRanges[location.Range] {
			kind = lsp.DocumentHighlightKindWrite
		}
		k := kind
		highlights = append(highlights, lsp.DocumentHighlight{Range: location.Range, Kind: &k})
	}

	if len(highlights) == 0 {
		return nil, false
	}
	return highlights, true
}

func (s *Snapshot) assignmentWriteRanges(targetName string) map[lsp.Range]bool {
	result := make(map[lsp.Range]bool)
	if s == nil || s.Program == nil || targetName == "" {
		return result
	}

	for _, stmt := range s.Program.Statements {
		s.collectStatementWriteRanges(stmt, targetName, result)
	}

	return result
}

func (s *Snapshot) collectStatementWriteRanges(stmt mast.Statement, targetName string, out map[lsp.Range]bool) {
	if isNilInterface(stmt) {
		return
	}

	switch node := stmt.(type) {
	case *mast.ExpressionStatement:
		s.collectExpressionWriteRanges(node.Expression, targetName, out)
	case *mast.LetStatement:
		s.collectExpressionWriteRanges(node.Value, targetName, out)
	case *mast.ReturnStatement:
		for _, value := range node.ReturnValues {
			s.collectExpressionWriteRanges(value, targetName, out)
		}
		if len(node.ReturnValues) == 0 {
			s.collectExpressionWriteRanges(node.ReturnValue, targetName, out)
		}
	case *mast.BlockStatement:
		for _, nested := range node.Statements {
			s.collectStatementWriteRanges(nested, targetName, out)
		}
	case *mast.ForStatement:
		s.collectStatementWriteRanges(node.Init, targetName, out)
		s.collectExpressionWriteRanges(node.Condition, targetName, out)
		s.collectExpressionWriteRanges(node.Post, targetName, out)
		s.collectStatementWriteRanges(node.Body, targetName, out)
	}
}

func (s *Snapshot) collectExpressionWriteRanges(expr mast.Expression, targetName string, out map[lsp.Range]bool) {
	if isNilInterface(expr) {
		return
	}

	switch node := expr.(type) {
	case *mast.AssignExpression:
		if ident, ok := node.Left.(*mast.Identifier); ok && ident != nil && ident.Value == targetName {
			if rng, ok := s.Program.RangeOf(ident); ok {
				out[localprotocol.ToLSPRange(rng)] = true
			}
		}
		s.collectExpressionWriteRanges(node.Left, targetName, out)
		s.collectExpressionWriteRanges(node.Value, targetName, out)
	case *mast.PrefixExpression:
		s.collectExpressionWriteRanges(node.Right, targetName, out)
	case *mast.InfixExpression:
		s.collectExpressionWriteRanges(node.Left, targetName, out)
		s.collectExpressionWriteRanges(node.Right, targetName, out)
	case *mast.IfExpression:
		s.collectExpressionWriteRanges(node.Condition, targetName, out)
		s.collectStatementWriteRanges(node.Consequence, targetName, out)
		s.collectStatementWriteRanges(node.Alternative, targetName, out)
	case *mast.FunctionLiteral:
		s.collectStatementWriteRanges(node.Body, targetName, out)
	case *mast.MacroLiteral:
		s.collectStatementWriteRanges(node.Body, targetName, out)
	case *mast.CallExpression:
		s.collectExpressionWriteRanges(node.Function, targetName, out)
		for _, arg := range node.Arguments {
			s.collectExpressionWriteRanges(arg, targetName, out)
		}
	case *mast.ArrayLiteral:
		for _, element := range node.Elements {
			s.collectExpressionWriteRanges(element, targetName, out)
		}
	case *mast.IndexExpression:
		s.collectExpressionWriteRanges(node.Left, targetName, out)
		s.collectExpressionWriteRanges(node.Index, targetName, out)
	case *mast.HashLiteral:
		for key, value := range node.Pairs {
			s.collectExpressionWriteRanges(key, targetName, out)
			s.collectExpressionWriteRanges(value, targetName, out)
		}
	case *mast.FieldExpression:
		s.collectExpressionWriteRanges(node.Left, targetName, out)
	case *mast.StructLiteral:
		for _, field := range node.Fields {
			if field == nil {
				continue
			}
			s.collectExpressionWriteRanges(field.Value, targetName, out)
		}
	}
}
