package ast

import "mutant/token"

type FloatLiteral struct {
	Token token.Token
	Value float64
}

func (fl *FloatLiteral) expressionNode()      {}
func (fl *FloatLiteral) TokenLiteral() string { return fl.Token.Literal }
func (fl *FloatLiteral) String() string {
	if fl == nil {
		return missingNode
	}
	return fl.Token.Literal
}
