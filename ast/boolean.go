package ast

import (
	"mutant/token"
)

type Boolean struct {
	Token token.Token
	Value bool
}

func (b *Boolean) expressionNode()      {}
func (b *Boolean) TokenLiteral() string { return b.Token.Literal }
func (b *Boolean) String() string {
	if b == nil {
		return missingNode
	}
	return b.Token.Literal
}
