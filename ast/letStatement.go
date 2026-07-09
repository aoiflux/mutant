package ast

import (
	"bytes"
	"mutant/token"
	"strings"
)

type LetStatement struct {
	Token token.Token // LET token
	Name  *Identifier
	Names []*Identifier
	Value Expression
}

func (ls *LetStatement) statementNode()       {}
func (ls *LetStatement) TokenLiteral() string { return ls.Token.Literal }
func (ls *LetStatement) String() string {
	var out bytes.Buffer
	out.WriteString(ls.TokenLiteral() + " ")
	if len(ls.Names) > 0 {
		names := make([]string, 0, len(ls.Names))
		for _, ident := range ls.Names {
			if ident == nil {
				continue
			}
			names = append(names, ident.String())
		}
		out.WriteString(strings.Join(names, ", "))
	} else if ls.Name != nil {
		out.WriteString(ls.Name.String())
	}
	out.WriteString(" = ")
	if ls.Value != nil {
		out.WriteString(ls.Value.String())
	}
	out.WriteString(";")
	return out.String()
}
