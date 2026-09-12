package ast

import (
	"bytes"

	"mutant/token"
)

// TemplateLiteral is a string literal holding at least one ${...} hole.
//
// A literal with no hole is still a StringLiteral, so this node only ever
// exists in a program that interpolates.
//
// The text is data and the holes are expressions, which is the distinction the
// node is built around: Texts[i] is the text before Parts[i], and the last
// entry of Texts is whatever follows the final hole, so len(Texts) is always
// len(Parts)+1 and any entry may be empty. Keeping text out of Parts means
// every walker that descends into Parts is looking at exactly the expressions
// the author wrote, and a hole a macro expanded into a string literal is still
// recognisably a hole.
//
// There is no format string. A hole is compiled where it stands, so nothing in
// the value is re-scanned at runtime and a `%` in the text is a percent sign.
type TemplateLiteral struct {
	Token token.Token
	Texts []string
	Parts []Expression
}

func (tl *TemplateLiteral) expressionNode()      {}
func (tl *TemplateLiteral) TokenLiteral() string { return tl.Token.Literal }

// String reprints the literal from its pieces rather than from the spelling on
// the token, so that a hole a macro rewrote prints as what it became. The
// formatter reads Token.Raw directly for the opposite reason: what it needs is
// the spelling the author wrote.
func (tl *TemplateLiteral) String() string {
	var out bytes.Buffer
	out.WriteString(`"`)
	for i, text := range tl.Texts {
		out.WriteString(text)
		if i >= len(tl.Parts) || tl.Parts[i] == nil {
			continue
		}
		out.WriteString("${")
		out.WriteString(tl.Parts[i].String())
		out.WriteString("}")
	}
	out.WriteString(`"`)
	return out.String()
}
