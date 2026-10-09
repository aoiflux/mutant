package ast

import (
	"bytes"
	"mutant/token"
	"strings"
)

type StructFieldValue struct {
	Name  *Identifier
	Value Expression
}

type StructLiteral struct {
	Token  token.Token
	Name   *Identifier
	Fields []*StructFieldValue
}

func (sl *StructLiteral) expressionNode()      {}
func (sl *StructLiteral) TokenLiteral() string { return sl.Token.Literal }
func (sl *StructLiteral) String() string {
	if sl == nil {
		return missingNode
	}
	var out bytes.Buffer
	fields := []string{}

	for _, f := range sl.Fields {
		if f == nil {
			fields = append(fields, missingNode)
			continue
		}
		fields = append(fields, render(f.Name)+": "+render(f.Value))
	}

	if sl.Name != nil {
		out.WriteString(sl.Name.String())
		out.WriteString(" ")
	}
	out.WriteString("{")
	out.WriteString(strings.Join(fields, ", "))
	out.WriteString("}")

	return out.String()
}
