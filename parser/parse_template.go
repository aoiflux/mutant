package parser

import (
	"fmt"
	"strings"

	"mutant/ast"
	"mutant/lexer"
	"mutant/token"
)

// parseTemplateLiteral builds the node for a string literal with ${...} holes.
//
// The lexer has already cut the literal into text and hole parts and recorded
// where each one starts, so all that is left here is to parse each hole's
// source as an expression and keep the text between them.
func (p *Parser) parseTemplateLiteral() ast.Expression {
	start := p.startMark()
	lit := &ast.TemplateLiteral{Token: p.curToken, Texts: []string{""}}

	for _, part := range p.curToken.Parts {
		if !part.Expression {
			// Text accumulates into the slot after the last accepted hole.
			// Two text parts in a row only happen when a hole between them
			// failed to parse, and merging them is right: the program is
			// already being rejected.
			lit.Texts[len(lit.Texts)-1] += part.Text
			continue
		}
		hole := p.parseHole(part)
		if hole == nil {
			continue
		}
		lit.Parts = append(lit.Parts, hole)
		lit.Texts = append(lit.Texts, "")
	}

	p.recordRange(lit, start)
	return lit
}

// parseHole parses one ${...} hole's source as a single expression.
//
// The source is parsed inside padding that puts its first character at the
// line and column it really occupies, so every position the sub-parser records
// is a position in this file rather than in a fragment. Only the byte offsets
// need correcting afterwards, since the padding is shorter than the text it
// stands in for; line and column come out right by construction.
//
// It is parsed as an expression rather than as a program on purpose. A hole
// holds no statement, so nothing in it should be asked for a terminating
// semicolon -- asking would put a missing-`;` complaint on every interpolated
// string in the file.
func (p *Parser) parseHole(part token.StringPart) ast.Expression {
	if strings.TrimSpace(part.Text) == "" {
		p.appendError(p.curToken, fmt.Sprintf(
			"empty ${} at line %d:%d: a hole needs an expression between the braces, and a literal ${ is written \\${",
			part.Start.Line, part.Start.Column))
		return nil
	}

	padding := strings.Repeat("\n", part.Start.Line-1) + strings.Repeat(" ", part.Start.Column-1)
	sub := New(lexer.New(padding + part.Text))

	if statementKeyword(sub.curToken.Type) {
		p.appendError(p.curToken, fmt.Sprintf(
			"%s at line %d:%d starts a statement, and a hole has to be an expression: it has to produce the value that goes into the string",
			sub.curToken.Type, part.Start.Line, part.Start.Column))
		return nil
	}

	expression := sub.parseExpression(LOWEST)
	if expression != nil && !sub.peekTokenIs(token.EOF) {
		p.appendError(p.curToken, fmt.Sprintf(
			"${%s} at line %d:%d holds more than one expression: a hole produces one value",
			strings.TrimSpace(part.Text), part.Start.Line, part.Start.Column))
		expression = nil
	}

	// The sub-parser's plain-text errors carry no position of their own, so
	// they are prefixed with the hole's. The typed errors need no such help:
	// their ranges are already file ranges, which is what the padding bought.
	for _, msg := range sub.errors {
		p.errors = append(p.errors, fmt.Sprintf("line %d:%d, inside ${...}: %s",
			part.Start.Line, part.Start.Column, msg))
	}
	p.typedErrors = append(p.typedErrors, sub.typedErrors...)
	p.recoverables = append(p.recoverables, sub.recoverables...)

	if expression == nil {
		return nil
	}

	// The padding spends one byte per line and one per column; the real text
	// starts wherever it starts. Everything the sub-parser recorded moves by
	// the difference.
	shift := part.Start.Offset - (part.Start.Line - 1) - (part.Start.Column - 1)
	if p.nodeRanges == nil {
		p.nodeRanges = make(map[ast.Node]ast.Range)
	}
	for node, rng := range sub.nodeRanges {
		p.nodeRanges[node] = rng.Shift(0, shift)
	}

	return expression
}

// statementKeyword reports whether a token can only begin a statement. A hole
// starting with one gets a message about what a hole is, rather than the
// parser's "no prefix parse function for LET".
func statementKeyword(t token.TokenType) bool {
	switch t {
	case token.LET, token.RETURN, token.FOR, token.BREAK, token.CONTINUE,
		token.STRUCT, token.ENUM, token.IMPORT:
		return true
	}
	return false
}
