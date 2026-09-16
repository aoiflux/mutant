package ast

import (
	"bytes"
	"mutant/token"
)

// MatchExpression is `match (subject) { pattern => body, ... }`.
//
// It is an expression rather than a statement because the thing people reach
// for it to do is produce a value -- `let label = match (status) { ... }`.
// Standing alone as a statement it behaves the way an `if` expression does,
// which is why ExpressionStatement.RequiresSemicolon exempts both.
//
// A match that no arm matches is a runtime error naming the value, not `null`.
// See the compiler's OpMatchFail for why that is not a silent fallback.
type MatchExpression struct {
	Token   token.Token // the `match` token
	Subject Expression
	Arms    []*MatchArm
}

func (me *MatchExpression) expressionNode()      {}
func (me *MatchExpression) TokenLiteral() string { return me.Token.Literal }
func (me *MatchExpression) String() string {
	var out bytes.Buffer

	out.WriteString("match (")
	if me.Subject != nil {
		out.WriteString(me.Subject.String())
	}
	out.WriteString(") {")
	for i, arm := range me.Arms {
		if arm == nil {
			continue
		}
		if i > 0 {
			out.WriteString(",")
		}
		out.WriteString(" ")
		out.WriteString(arm.String())
	}
	out.WriteString(" }")

	return out.String()
}

// MatchArm is one `pattern => body` of a match.
//
// Patterns holds the alternatives of `1 | 2 | 3`; an empty Patterns is the
// wildcard `_`. The wildcard is deliberately *not* stored as an Identifier
// named "_": every name-resolving walker would then have to special-case it,
// and the one that forgot would report the wildcard as an undefined name.
//
// Body is always a BlockStatement so that every walker has exactly one thing
// to walk, and so each walker arm is the arm it already wrote for
// IfExpression. Braced records which form the author wrote -- `=> "fine"` or
// `=> { "fine" }` -- because the formatter prints what was written rather than
// its own preferred spelling.
type MatchArm struct {
	Token    token.Token // the first token of the pattern
	Patterns []Expression
	Body     *BlockStatement
	Braced   bool
}

// IsWildcard reports whether this arm is the `_` arm, which matches anything
// and is therefore emitted with no comparison at all.
func (ma *MatchArm) IsWildcard() bool { return ma != nil && len(ma.Patterns) == 0 }

// TokenLiteral makes an arm an ast.Node so the parser can record its source
// range. Hover, folding, go-to-definition and the unreachable-code lint all
// read that side table rather than the tree, so an unrecorded node is
// invisible to them.
func (ma *MatchArm) TokenLiteral() string { return ma.Token.Literal }

func (ma *MatchArm) String() string {
	var out bytes.Buffer

	if ma.IsWildcard() {
		out.WriteString("_")
	}
	for i, pattern := range ma.Patterns {
		if i > 0 {
			out.WriteString(" | ")
		}
		if pattern != nil {
			out.WriteString(pattern.String())
		}
	}

	out.WriteString(" => ")
	if ma.Body != nil {
		// BlockStatement.String() prints its statements and no braces, the same
		// way IfExpression.String() prints a consequence, so both arm forms
		// render alike here. Braced exists for the formatter, which does have
		// to reproduce the author's choice.
		out.WriteString(ma.Body.String())
	}

	return out.String()
}
