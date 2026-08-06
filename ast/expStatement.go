package ast

import (
	"mutant/token"
)

type ExpressionStatement struct {
	Token      token.Token // first token of expression
	Expression Expression
}

func (es *ExpressionStatement) statementNode() {}

// RequiresSemicolon is true for every expression statement except one
// wrapping an `if`. `if` is an expression in Mutant, but when it stands
// alone as a statement its canonical form ends with the closing brace of a
// consequence or alternative block, so no terminator is written.
func (es *ExpressionStatement) RequiresSemicolon() bool {
	// A statement with no expression is the residue of a parse error; it is
	// never printed, so demanding a terminator would only add noise.
	if es == nil || es.Expression == nil {
		return false
	}
	_, isIf := es.Expression.(*IfExpression)
	return !isIf
}
func (es *ExpressionStatement) TokenLiteral() string { return es.Token.Literal }
func (es *ExpressionStatement) String() string {
	if es.Expression != nil {
		return es.Expression.String()
	}
	return ""
}
