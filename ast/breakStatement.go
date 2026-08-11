package ast

import "mutant/token"

type BreakStatement struct {
	Token token.Token
}

func (bs *BreakStatement) statementNode()          {}
func (bs *BreakStatement) RequiresSemicolon() bool { return true }
func (bs *BreakStatement) TokenLiteral() string    { return bs.Token.Literal }
func (bs *BreakStatement) String() string {
	return bs.TokenLiteral() + ";"
}
