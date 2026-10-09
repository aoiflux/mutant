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

func (ls *LetStatement) statementNode()          {}
func (ls *LetStatement) RequiresSemicolon() bool { return true }
func (ls *LetStatement) TokenLiteral() string    { return ls.Token.Literal }
func (ls *LetStatement) String() string {
	if ls == nil {
		return missingNode
	}
	var out bytes.Buffer
	out.WriteString(ls.TokenLiteral() + " ")
	if len(ls.Names) > 0 {
		names := make([]string, 0, len(ls.Names))
		for _, ident := range ls.Names {
			names = append(names, render(ident))
		}
		out.WriteString(strings.Join(names, ", "))
	} else if ls.Name != nil {
		out.WriteString(ls.Name.String())
	}
	out.WriteString(" = ")
	out.WriteString(render(ls.Value))
	out.WriteString(";")
	return out.String()
}
