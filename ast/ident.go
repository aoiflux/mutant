package ast

import "mutant/token"

type Identifier struct {
	Token token.Token // IDENT token
	Value string
}

func (i *Identifier) expressionNode()      {}
func (i *Identifier) TokenLiteral() string { return i.Token.Literal }
func (i *Identifier) String() string {
	if i == nil {
		return missingNode
	}
	return i.Value
}
