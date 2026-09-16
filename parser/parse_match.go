package parser

import (
	"fmt"

	"mutant/ast"
	"mutant/token"
)

// parseMatchExpression parses `match (subject) { pattern => body, ... }`.
//
// It is registered as a prefix parse function rather than a case in
// parseStatement, which is what makes `let label = match (x) { ... };` reach
// here at all -- `if` is registered the same way and for the same reason.
//
// The parentheses around the subject are not decoration. `{` is an infix
// operator at CALL precedence (a struct literal, `Point { x: 1 }`), so a
// paren-less `match x { ... }` would have its body swallowed as a struct
// literal named x and parse clean. That is the same hazard `while` documents.
func (p *Parser) parseMatchExpression() ast.Expression {
	start := p.startMark()
	exp := &ast.MatchExpression{Token: p.curToken}
	matchToken := p.curToken

	if !p.expectPeek(token.LPAREN) {
		return nil
	}

	p.nextToken()
	exp.Subject = p.parseExpression(LOWEST)
	if exp.Subject == nil {
		return nil
	}

	if !p.expectPeek(token.RPAREN) {
		return nil
	}
	if !p.expectPeek(token.LBRACE) {
		return nil
	}

	for !p.peekTokenIs(token.RBRACE) {
		if p.peekTokenIs(token.EOF) {
			p.appendError(p.peekToken, "match has no closing `}`")
			return nil
		}

		p.nextToken()
		arm := p.parseMatchArm()
		if arm == nil {
			return nil
		}
		exp.Arms = append(exp.Arms, arm)

		if p.peekTokenIs(token.COMMA) {
			p.nextToken()
			continue
		}
		if p.peekTokenIs(token.EOF) {
			// Running out of input after a well-formed arm means the closing
			// brace is missing, not the separator. Reporting the comma here
			// would point at the end of the file and name the wrong fix.
			p.appendError(p.peekToken, "match has no closing `}`")
			return nil
		}
		if !p.peekTokenIs(token.RBRACE) {
			msg := fmt.Sprintf("match arms are separated by `,`, got %s", p.peekToken.Type)
			p.appendError(p.peekToken, msg)
			return nil
		}
	}

	if !p.expectPeek(token.RBRACE) {
		return nil
	}

	// A match with no arms can never produce a value, so it is a match that
	// always fails. Refusing it here is cheaper than letting it compile to a
	// bare OpMatchFail and reporting it at run time.
	if len(exp.Arms) == 0 {
		p.appendError(matchToken, "match needs at least one arm")
		return nil
	}

	p.recordRange(exp, start)
	return exp
}

// parseMatchArm parses one `pattern => body`. On entry curToken is the first
// token of the pattern; on return it is the last token of the body.
func (p *Parser) parseMatchArm() *ast.MatchArm {
	start := p.startMark()
	arm := &ast.MatchArm{Token: p.curToken}

	patterns, ok := p.parseMatchPatterns()
	if !ok {
		return nil
	}
	arm.Patterns = patterns

	if !p.expectPeek(token.FATARROW) {
		return nil
	}

	p.nextToken()

	// `{` after `=>` is a block, never a hash literal -- the same rule `if`
	// uses for the brace after its condition. A hash-valued arm is written
	// `=> ({"k": 1})`, and anything else fails loudly at the `:` rather than
	// quietly producing the wrong shape.
	if p.curTokenIs(token.LBRACE) {
		arm.Braced = true
		arm.Body = p.parseBlockStatement()
		if arm.Body == nil {
			return nil
		}
		p.recordRange(arm, start)
		return arm
	}

	bodyToken := p.curToken
	value := p.parseExpression(LOWEST)
	if value == nil {
		return nil
	}

	// An unbraced body is stored as a one-statement block so that every walker
	// has a single shape to walk -- the same shape it already walks for an
	// if expression's consequence. Braced records which form was written, for
	// the formatter.
	arm.Body = &ast.BlockStatement{
		Token: bodyToken,
		Statements: []ast.Statement{
			&ast.ExpressionStatement{Token: bodyToken, Expression: value},
		},
	}

	p.recordRange(arm, start)
	return arm
}

// parseMatchPatterns parses `_`, or one or more alternatives separated by `|`.
// The second return value reports success; an empty slice with ok is the
// wildcard.
//
// Patterns have their own small grammar rather than going through
// parseExpression, and `|` is exactly why: it is the bitwise-or operator, so
// `1 | 2 | 3` parsed as an expression is the number 3. An arm written to match
// one of three values would have silently matched one value nobody wrote.
func (p *Parser) parseMatchPatterns() ([]ast.Expression, bool) {
	// The wildcard is represented by no patterns at all rather than by an
	// identifier named "_": every name-resolving walker in the language server
	// would otherwise have to know that this one name is not a name, and the
	// one that forgot would report it as undefined.
	if p.curTokenIs(token.IDENT) && p.curToken.Literal == "_" {
		return nil, true
	}

	patterns := []ast.Expression{}
	for {
		pattern := p.parseMatchPattern()
		if pattern == nil {
			return nil, false
		}
		patterns = append(patterns, pattern)

		if !p.peekTokenIs(token.PIPE) {
			return patterns, true
		}
		p.nextToken() // onto the `|`
		p.nextToken() // onto the next pattern
	}
}

// parseMatchPattern parses one alternative: a literal, a negated number, or a
// dotted path such as `Status.Ok`.
func (p *Parser) parseMatchPattern() ast.Expression {
	start := p.startMark()

	switch p.curToken.Type {
	case token.INT:
		return p.parseIntegerLiteral()
	case token.FLOAT:
		return p.parseFloatLiteral()
	case token.STRING:
		return p.parseStringLiteral()
	case token.TRUE, token.FALSE:
		return p.parseBoolean()

	case token.MINUS:
		operator := p.curToken
		if !p.peekTokenIs(token.INT) && !p.peekTokenIs(token.FLOAT) {
			p.appendError(p.peekToken, "`-` in a pattern must be followed by a number")
			return nil
		}
		p.nextToken()
		right := p.parseMatchPattern()
		if right == nil {
			return nil
		}
		exp := &ast.PrefixExpression{Token: operator, Operator: operator.Literal, Right: right}
		p.recordRange(exp, start)
		return exp

	case token.TEMPLATE:
		// "${x}" in a pattern would compare against something computed when
		// the match runs, which is a guard rather than a pattern. Guards are
		// deliberately not in this version, so say so instead of silently
		// accepting one shape of them.
		p.appendError(p.curToken, "an interpolated string is not a pattern; compare it in the arm body instead")
		return nil

	case token.IDENT:
		if !p.peekTokenIs(token.DOT) {
			msg := fmt.Sprintf(
				"`%s` is a name, not a pattern: a pattern is a literal, an enum variant like Status.Ok, or `_`",
				p.curToken.Literal)
			p.appendError(p.curToken, msg)
			return nil
		}

		var path ast.Expression = &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}
		p.recordRange(path, start)

		for p.peekTokenIs(token.DOT) {
			p.nextToken()
			dot := p.curToken
			if !p.expectPeek(token.IDENT) {
				return nil
			}
			fieldStart := p.startMark()
			field := &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}
			p.recordRange(field, fieldStart)

			path = &ast.FieldExpression{Token: dot, Left: path, Field: field}
			p.recordRange(path, start)
		}
		return path
	}

	msg := fmt.Sprintf(
		"expected a pattern -- a literal, an enum variant like Status.Ok, or `_` -- got %s",
		p.curToken.Type)
	p.appendError(p.curToken, msg)
	return nil
}
