package ast

import (
	"bytes"
	"mutant/token"
	"strings"
)

type ReturnStatement struct {
	Token        token.Token // RETURN token
	ReturnValue  Expression
	ReturnValues []Expression
}

func (rs *ReturnStatement) statementNode()       {}
func (rs *ReturnStatement) TokenLiteral() string { return rs.Token.Literal }
func (rs *ReturnStatement) String() string {
	var out bytes.Buffer

	out.WriteString(rs.TokenLiteral() + " ")
	if len(rs.ReturnValues) > 0 {
		parts := make([]string, 0, len(rs.ReturnValues))
		for _, expr := range rs.ReturnValues {
			if expr == nil {
				continue
			}
			parts = append(parts, expr.String())
		}
		out.WriteString(strings.Join(parts, ", "))
	} else if rs.ReturnValue != nil {
		out.WriteString(rs.ReturnValue.String())
	}

	out.WriteString(";")

	return out.String()
}
