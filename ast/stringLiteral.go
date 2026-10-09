package ast

import (
	"mutant/token"
)

type StringLiteral struct {
	Token token.Token
	Value string
}

func (sl *StringLiteral) expressionNode()      {}
func (sl *StringLiteral) TokenLiteral() string { return sl.Token.Literal }
func (sl *StringLiteral) String() string {
	if sl == nil {
		return missingNode
	}
	return sl.Token.Literal
}
