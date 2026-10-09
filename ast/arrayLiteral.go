package ast

import (
	"bytes"
	"mutant/token"
	"strings"
)

type ArrayLiteral struct {
	Token    token.Token
	Elements []Expression
}

func (al *ArrayLiteral) expressionNode()      {}
func (al *ArrayLiteral) TokenLiteral() string { return al.Token.Literal }
func (al *ArrayLiteral) String() string {
	if al == nil {
		return missingNode
	}
	var out bytes.Buffer
	elements := []string{}

	for _, el := range al.Elements {
		elements = append(elements, render(el))
	}

	out.WriteString("[")
	out.WriteString(strings.Join(elements, ", "))
	out.WriteString("]")

	return out.String()
}
