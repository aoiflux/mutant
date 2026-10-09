package ast

import (
	"bytes"
	"mutant/token"
)

type InfixExpression struct {
	Token    token.Token
	Left     Expression
	Operator string
	Right    Expression
}

func (ie *InfixExpression) expressionNode()      {}
func (ie *InfixExpression) TokenLiteral() string { return ie.Token.Literal }
func (ie *InfixExpression) String() string {
	if ie == nil {
		return missingNode
	}
	var out bytes.Buffer
	out.WriteString("(")
	out.WriteString(render(ie.Left))
	out.WriteString(" " + ie.Operator + " ")
	out.WriteString(render(ie.Right))
	out.WriteString(")")
	return out.String()
}
