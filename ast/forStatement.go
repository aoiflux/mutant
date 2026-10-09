package ast

import (
	"bytes"
	"mutant/token"
)

type ForStatement struct {
	Token     token.Token
	Init      Statement
	Condition Expression
	Post      Expression
	Body      *BlockStatement
}

func (fs *ForStatement) statementNode() {}

// RequiresSemicolon is false: a `for` statement ends with its body's `}`.
// The semicolons inside the header are structural, not terminators.
func (fs *ForStatement) RequiresSemicolon() bool { return false }
func (fs *ForStatement) TokenLiteral() string    { return fs.Token.Literal }
func (fs *ForStatement) String() string {
	if fs == nil {
		return missingNode
	}
	var out bytes.Buffer

	out.WriteString("for (")
	out.WriteString(render(fs.Init))
	out.WriteString("; ")
	out.WriteString(render(fs.Condition))
	out.WriteString("; ")
	out.WriteString(render(fs.Post))
	out.WriteString(") ")
	out.WriteString(render(fs.Body))

	return out.String()
}
