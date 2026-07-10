package analyzer

import (
	"fmt"
	"sort"

	mast "mutant/ast"
	"mutant/builtin"
	localprotocol "mutant/lsp/internal/protocol"
	"mutant/token"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func (s *Snapshot) SignatureHelp(pos lsp.Position) (*lsp.SignatureHelp, bool) {
	if s == nil || s.Program == nil {
		return nil, false
	}

	call, ok := s.callExpressionAt(pos)
	if !ok {
		return nil, false
	}

	sig, ok := s.signatureInformationForCall(call, pos)
	if !ok {
		return nil, false
	}

	activeSignature := lsp.UInteger(0)
	activeParameter := lsp.UInteger(s.activeParameterForCall(call, pos))

	result := &lsp.SignatureHelp{
		Signatures:      []lsp.SignatureInformation{sig},
		ActiveSignature: &activeSignature,
	}

	if len(sig.Parameters) > 0 {
		if int(activeParameter) >= len(sig.Parameters) {
			activeParameter = lsp.UInteger(len(sig.Parameters) - 1)
		}
		result.ActiveParameter = &activeParameter
	}

	return result, true
}

func (s *Snapshot) callExpressionAt(pos lsp.Position) (*mast.CallExpression, bool) {
	if s == nil || s.Program == nil || s.Program.NodePositions == nil {
		return nil, false
	}

	var best *mast.CallExpression
	bestSize := int(^uint(0) >> 1)

	for node, rng := range s.Program.NodePositions {
		call, ok := node.(*mast.CallExpression)
		if !ok || call == nil || !rng.IsValid() {
			continue
		}
		if !localprotocol.ContainsPosition(rng, pos) {
			continue
		}
		size := rng.End.Offset - rng.Start.Offset
		if size < bestSize {
			best = call
			bestSize = size
		}
	}

	if best == nil {
		return nil, false
	}
	return best, true
}

func (s *Snapshot) signatureInformationForCall(call *mast.CallExpression, pos lsp.Position) (lsp.SignatureInformation, bool) {
	if call == nil || call.Function == nil {
		return lsp.SignatureInformation{}, false
	}

	switch fn := call.Function.(type) {
	case *mast.FunctionLiteral:
		return functionLiteralSignature(fn, functionDisplayName("fn", fn.Name)), true
	case *mast.Identifier:
		if fn == nil || fn.Value == "" {
			return lsp.SignatureInformation{}, false
		}
		if builtin.GetBuiltinByName(fn.Value) != nil {
			if sig, ok := builtinSignatureInformation(fn.Value); ok {
				return sig, true
			}
			return lsp.SignatureInformation{Label: fmt.Sprintf("%s(...)", fn.Value)}, true
		}

		resolved, ok := s.resolveDefinition(positionInsideIdentifier(s, fn, pos))
		if !ok || resolved.ident == nil {
			return lsp.SignatureInformation{}, false
		}
		literal, ok := s.functionLiteralForBindingIdent(resolved.ident)
		if !ok {
			return lsp.SignatureInformation{}, false
		}
		return functionLiteralSignature(literal, functionDisplayName(fn.Value, literal.Name)), true
	default:
		return lsp.SignatureInformation{}, false
	}
}

func functionLiteralSignature(fn *mast.FunctionLiteral, displayName string) lsp.SignatureInformation {
	if fn == nil {
		return lsp.SignatureInformation{Label: fmt.Sprintf("%s()", displayName)}
	}

	paramNames := make([]string, 0, len(fn.Parameters))
	parameters := make([]lsp.ParameterInformation, 0, len(fn.Parameters))
	for _, p := range fn.Parameters {
		if p == nil {
			continue
		}
		paramNames = append(paramNames, p.Value)
		parameters = append(parameters, lsp.ParameterInformation{Label: p.Value})
	}

	return lsp.SignatureInformation{
		Label:      fmt.Sprintf("%s(%s)", displayName, joinParamNames(paramNames)),
		Parameters: parameters,
	}
}

func functionDisplayName(fallback, literalName string) string {
	if literalName != "" {
		return literalName
	}
	return fallback
}

func joinParamNames(params []string) string {
	if len(params) == 0 {
		return ""
	}
	out := params[0]
	for i := 1; i < len(params); i++ {
		out += ", " + params[i]
	}
	return out
}

func (s *Snapshot) activeParameterForCall(call *mast.CallExpression, pos lsp.Position) int {
	if s == nil || s.Program == nil || call == nil || len(call.Arguments) == 0 {
		return 0
	}

	type argRange struct {
		index int
		rng   mast.Range
	}
	ranges := make([]argRange, 0, len(call.Arguments))
	for i, arg := range call.Arguments {
		rng, ok := s.Program.RangeOf(arg)
		if !ok {
			continue
		}
		ranges = append(ranges, argRange{index: i, rng: rng})
	}

	if len(ranges) == 0 {
		return 0
	}

	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].rng.Start.Line != ranges[j].rng.Start.Line {
			return ranges[i].rng.Start.Line < ranges[j].rng.Start.Line
		}
		return ranges[i].rng.Start.Column < ranges[j].rng.Start.Column
	})

	for _, item := range ranges {
		if localprotocol.ContainsPosition(item.rng, pos) {
			return item.index
		}
		if positionBeforeTokenPosition(pos, item.rng.Start) {
			return item.index
		}
	}

	return ranges[len(ranges)-1].index
}

func positionBeforeTokenPosition(pos lsp.Position, tokenPos token.Position) bool {
	line := int(pos.Line) + 1
	column := int(pos.Character) + 1
	if line != tokenPos.Line {
		return line < tokenPos.Line
	}
	return column < tokenPos.Column
}

func positionInsideIdentifier(s *Snapshot, ident *mast.Identifier, fallback lsp.Position) lsp.Position {
	if s == nil || s.Program == nil || ident == nil {
		return fallback
	}
	rng, ok := s.Program.RangeOf(ident)
	if !ok {
		return fallback
	}
	return lsp.Position{Line: lsp.UInteger(rng.Start.Line - 1), Character: lsp.UInteger(rng.Start.Column - 1)}
}

func (s *Snapshot) functionLiteralForBindingIdent(target *mast.Identifier) (*mast.FunctionLiteral, bool) {
	if s == nil || s.Program == nil || target == nil {
		return nil, false
	}

	for _, stmt := range s.Program.Statements {
		if literal, ok := functionLiteralInStatementForIdent(stmt, target); ok {
			return literal, true
		}
	}
	return nil, false
}

func functionLiteralInStatementForIdent(stmt mast.Statement, target *mast.Identifier) (*mast.FunctionLiteral, bool) {
	switch node := stmt.(type) {
	case *mast.LetStatement:
		names := node.Names
		if len(names) == 0 && node.Name != nil {
			names = []*mast.Identifier{node.Name}
		}
		for _, name := range names {
			if name == target {
				literal, ok := node.Value.(*mast.FunctionLiteral)
				if ok && literal != nil {
					return literal, true
				}
				return nil, false
			}
		}
		if node.Value != nil {
			return functionLiteralInExpressionForIdent(node.Value, target)
		}
	case *mast.ReturnStatement:
		for _, expr := range node.ReturnValues {
			if literal, ok := functionLiteralInExpressionForIdent(expr, target); ok {
				return literal, true
			}
		}
		if len(node.ReturnValues) == 0 && node.ReturnValue != nil {
			return functionLiteralInExpressionForIdent(node.ReturnValue, target)
		}
	case *mast.ExpressionStatement:
		if node.Expression != nil {
			return functionLiteralInExpressionForIdent(node.Expression, target)
		}
	case *mast.BlockStatement:
		for _, inner := range node.Statements {
			if literal, ok := functionLiteralInStatementForIdent(inner, target); ok {
				return literal, true
			}
		}
	case *mast.ForStatement:
		if node.Init != nil {
			if literal, ok := functionLiteralInStatementForIdent(node.Init, target); ok {
				return literal, true
			}
		}
		if node.Condition != nil {
			if literal, ok := functionLiteralInExpressionForIdent(node.Condition, target); ok {
				return literal, true
			}
		}
		if node.Post != nil {
			if literal, ok := functionLiteralInExpressionForIdent(node.Post, target); ok {
				return literal, true
			}
		}
		if node.Body != nil {
			return functionLiteralInStatementForIdent(node.Body, target)
		}
	}

	return nil, false
}

func functionLiteralInExpressionForIdent(expr mast.Expression, target *mast.Identifier) (*mast.FunctionLiteral, bool) {
	switch node := expr.(type) {
	case *mast.FunctionLiteral:
		return nil, false
	case *mast.IfExpression:
		if node.Condition != nil {
			if literal, ok := functionLiteralInExpressionForIdent(node.Condition, target); ok {
				return literal, true
			}
		}
		if node.Consequence != nil {
			if literal, ok := functionLiteralInStatementForIdent(node.Consequence, target); ok {
				return literal, true
			}
		}
		if node.Alternative != nil {
			if literal, ok := functionLiteralInStatementForIdent(node.Alternative, target); ok {
				return literal, true
			}
		}
	case *mast.CallExpression:
		if node.Function != nil {
			if literal, ok := functionLiteralInExpressionForIdent(node.Function, target); ok {
				return literal, true
			}
		}
		for _, arg := range node.Arguments {
			if literal, ok := functionLiteralInExpressionForIdent(arg, target); ok {
				return literal, true
			}
		}
	case *mast.PrefixExpression:
		if node.Right != nil {
			return functionLiteralInExpressionForIdent(node.Right, target)
		}
	case *mast.InfixExpression:
		if node.Left != nil {
			if literal, ok := functionLiteralInExpressionForIdent(node.Left, target); ok {
				return literal, true
			}
		}
		if node.Right != nil {
			if literal, ok := functionLiteralInExpressionForIdent(node.Right, target); ok {
				return literal, true
			}
		}
	case *mast.IndexExpression:
		if node.Left != nil {
			if literal, ok := functionLiteralInExpressionForIdent(node.Left, target); ok {
				return literal, true
			}
		}
		if node.Index != nil {
			if literal, ok := functionLiteralInExpressionForIdent(node.Index, target); ok {
				return literal, true
			}
		}
	case *mast.AssignExpression:
		if node.Left != nil {
			if literal, ok := functionLiteralInExpressionForIdent(node.Left, target); ok {
				return literal, true
			}
		}
		if node.Value != nil {
			if literal, ok := functionLiteralInExpressionForIdent(node.Value, target); ok {
				return literal, true
			}
		}
	case *mast.FieldExpression:
		if node.Left != nil {
			return functionLiteralInExpressionForIdent(node.Left, target)
		}
	case *mast.StructLiteral:
		if node.Name != nil {
			if literal, ok := functionLiteralInExpressionForIdent(node.Name, target); ok {
				return literal, true
			}
		}
		for _, field := range node.Fields {
			if field != nil && field.Value != nil {
				if literal, ok := functionLiteralInExpressionForIdent(field.Value, target); ok {
					return literal, true
				}
			}
		}
	case *mast.ArrayLiteral:
		for _, element := range node.Elements {
			if literal, ok := functionLiteralInExpressionForIdent(element, target); ok {
				return literal, true
			}
		}
	case *mast.HashLiteral:
		for key, value := range node.Pairs {
			if literal, ok := functionLiteralInExpressionForIdent(key, target); ok {
				return literal, true
			}
			if literal, ok := functionLiteralInExpressionForIdent(value, target); ok {
				return literal, true
			}
		}
	case *mast.MacroLiteral:
		if node.Body != nil {
			return functionLiteralInStatementForIdent(node.Body, target)
		}
	}

	return nil, false
}
