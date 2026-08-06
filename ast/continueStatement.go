package ast

import "mutant/token"

type ContinueStatement struct {
	Token token.Token
}

func (cs *ContinueStatement) statementNode()          {}
func (cs *ContinueStatement) RequiresSemicolon() bool { return true }
func (cs *ContinueStatement) TokenLiteral() string    { return cs.Token.Literal }
func (cs *ContinueStatement) String() string {
	return cs.TokenLiteral() + ";"
}
