package ast

import (
	"bytes"
	"mutant/token"
	"strings"
)

type CallExpression struct {
	Token     token.Token
	Function  Expression
	Arguments []Expression
}

func (ce *CallExpression) expressionNode()      {}
func (ce *CallExpression) TokenLiteral() string { return ce.Token.Literal }
func (ce *CallExpression) String() string {
	if ce == nil {
		return missingNode
	}
	var out bytes.Buffer
	args := []string{}
	for _, a := range ce.Arguments {
		// A nil argument is printed, not skipped: dropping it rendered
		// `f(1, , 2)` as a call of two arguments.
		args = append(args, render(a))
	}
	out.WriteString(render(ce.Function))
	out.WriteString("(")
	out.WriteString(strings.Join(args, ", "))
	out.WriteString(")")
	return out.String()
}
