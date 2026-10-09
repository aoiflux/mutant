package ast

import (
	"bytes"
	"mutant/token"
)

type IfExpression struct {
	Token       token.Token
	Condition   Expression
	Consequence *BlockStatement
	Alternative *BlockStatement
}

func (ie *IfExpression) expressionNode()      {}
func (ie *IfExpression) TokenLiteral() string { return ie.Token.Literal }
func (ie *IfExpression) String() string {
	if ie == nil {
		return missingNode
	}
	var out bytes.Buffer
	out.WriteString("if")
	out.WriteString(render(ie.Condition))
	out.WriteString(" ")
	out.WriteString(render(ie.Consequence))
	if ie.Alternative != nil {
		out.WriteString("else ")
		out.WriteString(ie.Alternative.String())
	}
	return out.String()
}
