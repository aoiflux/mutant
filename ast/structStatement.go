package ast

import (
	"bytes"
	"mutant/token"
	"strings"
)

type StructStatement struct {
	Token  token.Token
	Name   *Identifier
	Fields []*Identifier
}

func (ss *StructStatement) statementNode() {}

// RequiresSemicolon is false: a struct declaration ends with `}`. Its field
// list is semicolon-separated internally, which the formatter emits.
func (ss *StructStatement) RequiresSemicolon() bool { return false }
func (ss *StructStatement) TokenLiteral() string    { return ss.Token.Literal }
func (ss *StructStatement) String() string {
	var out bytes.Buffer
	fields := []string{}

	for _, f := range ss.Fields {
		fields = append(fields, f.String())
	}

	out.WriteString("struct ")
	if ss.Name != nil {
		out.WriteString(ss.Name.String())
	}
	out.WriteString(" {")
	if len(fields) > 0 {
		out.WriteString(" ")
		out.WriteString(strings.Join(fields, "; "))
		out.WriteString(";")
	}
	out.WriteString(" }")

	return out.String()
}
