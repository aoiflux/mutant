package ast

import (
	"bytes"
	"mutant/token"
)

type PrefixExpression struct {
	Token    token.Token // the prefix token
	Operator string
	Right    Expression
}

func (pe *PrefixExpression) expressionNode()      {}
func (pe *PrefixExpression) TokenLiteral() string { return pe.Token.Literal }
func (pe *PrefixExpression) String() string {
	if pe == nil {
		return missingNode
	}
	var out bytes.Buffer
	out.WriteString("(")
	out.WriteString(pe.Operator)
	out.WriteString(render(pe.Right))
	out.WriteString(")")
	return out.String()
}
