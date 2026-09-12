package ast

import (
	"bytes"
	"mutant/token"
)

// ForInStatement is `for (v in xs)` and `for (k, v in xs)`.
//
// It is a separate node from ForStatement rather than an overload of it. The
// two share no header fields, and folding them together would mean every
// walker that handles a loop has to ask which kind it is holding -- a question
// a walker can forget to ask, producing a silent wrong answer. A distinct type
// makes the type switch ask it.
//
// Key is nil in the one-binding form. What the two bindings mean depends on
// what is being iterated, and the rule is that a single binding yields the
// thing the collection is made of: an array's element, but a hash's key.
type ForInStatement struct {
	Token    token.Token
	Key      *Identifier
	Value    *Identifier
	Iterable Expression
	Body     *BlockStatement
}

func (fs *ForInStatement) statementNode() {}

// RequiresSemicolon is false: the statement ends with its body's `}`.
func (fs *ForInStatement) RequiresSemicolon() bool { return false }
func (fs *ForInStatement) TokenLiteral() string    { return fs.Token.Literal }
func (fs *ForInStatement) String() string {
	var out bytes.Buffer

	out.WriteString("for (")
	if fs.Key != nil {
		out.WriteString(fs.Key.String())
		out.WriteString(", ")
	}
	if fs.Value != nil {
		out.WriteString(fs.Value.String())
	}
	out.WriteString(" in ")
	if fs.Iterable != nil {
		out.WriteString(fs.Iterable.String())
	}
	out.WriteString(") ")
	if fs.Body != nil {
		out.WriteString(fs.Body.String())
	}

	return out.String()
}
