package ast

import (
	"bytes"
	"mutant/token"
)

type BlockStatement struct {
	Token      token.Token
	Statements []Statement
}

func (bs *BlockStatement) statementNode() {}

// RequiresSemicolon is false: a block's canonical form ends with `}`.
func (bs *BlockStatement) RequiresSemicolon() bool { return false }
func (bs *BlockStatement) TokenLiteral() string    { return bs.Token.Literal }
func (bs *BlockStatement) String() string {
	var out bytes.Buffer

	for _, s := range bs.Statements {
		out.WriteString(s.String())
	}

	return out.String()
}
