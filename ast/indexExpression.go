package ast

import (
	"bytes"
	"mutant/token"
)

type IndexExpression struct {
	Token token.Token
	Left  Expression
	Index Expression
}

func (ie *IndexExpression) expressionNode()      {}
func (ie *IndexExpression) TokenLiteral() string { return ie.Token.Literal }
func (ie *IndexExpression) String() string {
	if ie == nil {
		return missingNode
	}
	var out bytes.Buffer

	out.WriteString("(")
	out.WriteString(render(ie.Left))
	out.WriteString("[")
	out.WriteString(render(ie.Index))
	out.WriteString("])")

	return out.String()
}
