package ast

import (
	"bytes"
	"mutant/token"
)

type FieldExpression struct {
	Token token.Token
	Left  Expression
	Field *Identifier
}

func (fe *FieldExpression) expressionNode()      {}
func (fe *FieldExpression) TokenLiteral() string { return fe.Token.Literal }
func (fe *FieldExpression) String() string {
	if fe == nil {
		return missingNode
	}
	var out bytes.Buffer

	out.WriteString("(")
	out.WriteString(render(fe.Left))
	out.WriteString(".")
	out.WriteString(render(fe.Field))
	out.WriteString(")")

	return out.String()
}
