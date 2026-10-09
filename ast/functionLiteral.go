package ast

import (
	"bytes"
	"fmt"
	"mutant/token"
	"strings"
)

type FunctionLiteral struct {
	Token      token.Token
	Parameters []*Identifier
	Body       *BlockStatement
	Name       string
}

func (fl *FunctionLiteral) expressionNode()      {}
func (fl *FunctionLiteral) TokenLiteral() string { return fl.Token.Literal }
func (fl *FunctionLiteral) String() string {
	if fl == nil {
		return missingNode
	}
	var out bytes.Buffer
	params := []string{}

	for _, p := range fl.Parameters {
		params = append(params, render(p))
	}

	out.WriteString(fl.TokenLiteral())
	if fl.Name != "" {
		out.WriteString(fmt.Sprintf("<%s>", fl.Name))
	}
	out.WriteString("(")
	out.WriteString(strings.Join(params, ", "))
	out.WriteString(") ")
	out.WriteString(render(fl.Body))

	return out.String()
}
