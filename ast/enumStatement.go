package ast

import (
	"bytes"
	"mutant/token"
	"strings"
)

type EnumStatement struct {
	Token    token.Token
	Name     *Identifier
	Variants []*Identifier
}

func (es *EnumStatement) statementNode() {}

// RequiresSemicolon is false: an enum declaration ends with `}`.
func (es *EnumStatement) RequiresSemicolon() bool { return false }
func (es *EnumStatement) TokenLiteral() string    { return es.Token.Literal }
func (es *EnumStatement) String() string {
	var out bytes.Buffer
	variants := []string{}

	for _, v := range es.Variants {
		variants = append(variants, v.String())
	}

	out.WriteString("enum ")
	if es.Name != nil {
		out.WriteString(es.Name.String())
	}
	out.WriteString(" {")
	if len(variants) > 0 {
		out.WriteString(" ")
		out.WriteString(strings.Join(variants, ", "))
	}
	out.WriteString(" }")

	return out.String()
}
