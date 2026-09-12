package ast

import (
	"bytes"
	"mutant/token"
)

// WhileStatement is `while (cond) { ... }`.
//
// It is deliberately not sugar for a ForStatement with no init and no post.
// The two compile to almost the same instructions, but a shared node would
// make String() and the formatter print `for (; c; )` for source that said
// `while (c)` -- the tooling rewriting the author's choice of construct.
type WhileStatement struct {
	Token     token.Token
	Condition Expression
	Body      *BlockStatement
}

func (ws *WhileStatement) statementNode() {}

// RequiresSemicolon is false: a `while` ends with its body's `}`.
func (ws *WhileStatement) RequiresSemicolon() bool { return false }
func (ws *WhileStatement) TokenLiteral() string    { return ws.Token.Literal }
func (ws *WhileStatement) String() string {
	var out bytes.Buffer

	out.WriteString("while (")
	if ws.Condition != nil {
		out.WriteString(ws.Condition.String())
	}
	out.WriteString(") ")
	if ws.Body != nil {
		out.WriteString(ws.Body.String())
	}

	return out.String()
}
