package ast

import (
	"bytes"
	"mutant/token"
)

type AssignExpression struct {
	Token token.Token
	Left  Expression
	Value Expression
	// Operator is empty for a plain assignment (`x = v`). For a compound
	// assignment it holds the base binary operator ("+", "-", "*", "/", "%"),
	// so `x += v` is evaluated as `x = x <op> v`.
	Operator string
	// Postfix is empty normally; it holds "++" or "--" when this node came from
	// a postfix increment/decrement, purely so the operator can be printed back
	// in its original form. Such nodes always have Operator set ("+"/"-") and a
	// synthetic Value of 1.
	Postfix string
}

func (ae *AssignExpression) expressionNode()      {}
func (ae *AssignExpression) TokenLiteral() string { return ae.Token.Literal }
func (ae *AssignExpression) String() string {
	var out bytes.Buffer

	out.WriteString("(")
	if ae.Left != nil {
		out.WriteString(ae.Left.String())
	}
	if ae.Postfix != "" {
		out.WriteString(ae.Postfix)
		out.WriteString(")")
		return out.String()
	}
	if ae.Operator != "" {
		out.WriteString(" " + ae.Operator + "= ")
	} else {
		out.WriteString(" = ")
	}
	if ae.Value != nil {
		out.WriteString(ae.Value.String())
	}
	out.WriteString(")")

	return out.String()
}
