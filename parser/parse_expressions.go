package parser

import (
	"fmt"
	"mutant/ast"
	"mutant/token"
)

func (p *Parser) parseIfExpression() ast.Expression {
	start := p.startMark()
	exp := &ast.IfExpression{Token: p.curToken}
	if !p.expectPeek(token.LPAREN) {
		return nil
	}

	p.nextToken()
	exp.Condition = p.parseExpression(LOWEST)

	if !p.expectPeek(token.RPAREN) {
		return nil
	}
	if !p.expectPeek(token.LBRACE) {
		return nil
	}

	exp.Consequence = p.parseBlockStatement()

	if p.peekTokenIs(token.ELSE) {
		p.nextToken()
		if p.peekTokenIs(token.IF) {
			p.nextToken()
			alternative := p.parseIfExpression()
			if alternative == nil {
				return nil
			}

			alternativeIf, ok := alternative.(*ast.IfExpression)
			if !ok || alternativeIf == nil {
				msg := fmt.Sprintf("expected else-if alternative to parse as if expression, got %T", alternative)
				p.appendError(p.curToken, msg)
				return nil
			}

			exp.Alternative = &ast.BlockStatement{
				Token: token.Token{Type: token.ELSE, Literal: "else", Start: p.curToken.Start, End: p.curToken.End},
				Statements: []ast.Statement{
					&ast.ExpressionStatement{Token: alternativeIf.Token, Expression: alternativeIf},
				},
			}
		} else {
			if !p.expectPeek(token.LBRACE) {
				return nil
			}
			exp.Alternative = p.parseBlockStatement()
		}
	}

	p.recordRange(exp, start)
	return exp
}

func (p *Parser) parsePrefixExpression() ast.Expression {
	// defer untrace(trace("parsePrefixExpression"))

	start := p.startMark()
	expression := &ast.PrefixExpression{
		Token:    p.curToken,
		Operator: p.curToken.Literal,
	}

	p.nextToken()
	expression.Right = p.parseExpression(PREFIX)

	p.recordRange(expression, start)
	return expression
}

func (p *Parser) parseInfixExpression(left ast.Expression) ast.Expression {
	// defer untrace(trace("parseInfixExpression"))

	// The left-hand side has already been parsed; its range is registered
	// against the sub-node. For the InfixExpression as a whole we use the
	// left operand's start (if known) so hovers cover the entire binary
	// expression rather than just the operator onwards.
	start := p.curToken.Start
	if r, ok := p.nodeRanges[left]; ok {
		start = r.Start
	}
	expression := &ast.InfixExpression{
		Token:    p.curToken,
		Operator: p.curToken.Literal,
		Left:     left,
	}

	prec := p.curPrecedence()
	p.nextToken()
	expression.Right = p.parseExpression(prec)

	p.recordRange(expression, start)
	return expression
}

func (p *Parser) parseGroupedExpression() ast.Expression {
	p.nextToken()
	exp := p.parseExpression(LOWEST)
	if !p.expectPeek(token.RPAREN) {
		return nil
	}
	return exp
}

func (p *Parser) parseExpression(precedence int) ast.Expression {
	// defer untrace(trace("parseExpression"))

	prefix := p.prefixParseFns[p.curToken.Type]
	if prefix == nil {
		p.notPrefixParseFnError(p.curToken.Type)
		return nil
	}

	leftExp := prefix()

	for !p.peekTokenIs(token.SEMICOLON) && precedence < p.peekPrecedence() {
		infix := p.infixParseFns[p.peekToken.Type]
		if infix == nil {
			return leftExp
		}
		p.nextToken()
		leftExp = infix(leftExp)
	}

	return leftExp
}

func (p *Parser) parseExpressionStatement() *ast.ExpressionStatement {
	// defer untrace(trace("parseExpressionStatement"))

	start := p.startMark()
	stmt := &ast.ExpressionStatement{Token: p.curToken}
	stmt.Expression = p.parseExpression(LOWEST)

	if p.peekTokenIs(token.SEMICOLON) {
		p.nextToken()
	}

	p.recordRange(stmt, start)
	return stmt
}

func (p *Parser) parseCallExpression(fun ast.Expression) ast.Expression {
	start := p.curToken.Start
	if r, ok := p.nodeRanges[fun]; ok {
		start = r.Start
	}
	exp := &ast.CallExpression{Token: p.curToken, Function: fun}
	exp.Arguments = p.parseExpressionList(token.RPAREN)
	p.recordRange(exp, start)
	return exp
}

func (p *Parser) parseExpressionList(end token.TokenType) []ast.Expression {
	list := []ast.Expression{}

	if p.peekTokenIs(end) {
		p.nextToken()
		return list
	}

	p.nextToken()
	for !p.curTokenIs(token.EOF) {
		exp := p.parseExpression(LOWEST)
		if exp != nil {
			list = append(list, exp)
		}

		if p.peekTokenIs(token.COMMA) {
			p.nextToken()
			p.nextToken()
			continue
		}

		if p.peekTokenIs(end) {
			p.nextToken()
			return list
		}

		if p.curTokenIs(end) {
			return list
		}

		msg := fmt.Sprintf("expected next token to be %s or %s, but got %s instead", token.COMMA, end, p.peekToken.Type)
		p.appendError(p.peekToken, msg)

		stop := p.synchronizeToTokenTypes(token.COMMA, end, token.SEMICOLON, token.RBRACE)
		if stop == token.COMMA {
			p.nextToken()
			continue
		}
		if stop == end {
			return list
		}

		return list
	}

	return list
}

func (p *Parser) parseIndexExpression(left ast.Expression) ast.Expression {
	start := p.curToken.Start
	if r, ok := p.nodeRanges[left]; ok {
		start = r.Start
	}
	exp := &ast.IndexExpression{Token: p.curToken, Left: left}
	p.nextToken()
	exp.Index = p.parseExpression(LOWEST)
	if !p.expectPeek(token.RSQUARE) {
		return nil
	}
	p.recordRange(exp, start)
	return exp
}

func (p *Parser) parseAssignExpression(left ast.Expression) ast.Expression {
	switch left.(type) {
	case *ast.Identifier, *ast.FieldExpression:
	default:
		msg := fmt.Sprintf("invalid assignment target: %T", left)
		p.appendError(p.curToken, msg)
		return nil
	}

	start := p.curToken.Start
	if r, ok := p.nodeRanges[left]; ok {
		start = r.Start
	}
	exp := &ast.AssignExpression{Token: p.curToken, Left: left}
	precedence := p.curPrecedence()
	p.nextToken()
	exp.Value = p.parseExpression(precedence - 1)

	p.recordRange(exp, start)
	return exp
}

func (p *Parser) parseFieldExpression(left ast.Expression) ast.Expression {
	start := p.curToken.Start
	if r, ok := p.nodeRanges[left]; ok {
		start = r.Start
	}
	exp := &ast.FieldExpression{Token: p.curToken, Left: left}

	if !p.expectPeek(token.IDENT) {
		return nil
	}

	fieldStart := p.startMark()
	exp.Field = &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}
	p.recordRange(exp.Field, fieldStart)
	p.recordRange(exp, start)
	return exp
}

func (p *Parser) parseStructLiteralExpression(left ast.Expression) ast.Expression {
	name, ok := left.(*ast.Identifier)
	if !ok {
		return left
	}

	start := p.curToken.Start
	if r, ok := p.nodeRanges[left]; ok {
		start = r.Start
	}
	lit := &ast.StructLiteral{Token: p.curToken, Name: name, Fields: []*ast.StructFieldValue{}}

	for !p.peekTokenIs(token.RBRACE) && !p.peekTokenIs(token.EOF) {
		p.nextToken()
		if !p.curTokenIs(token.IDENT) {
			msg := fmt.Sprintf("expected struct literal field identifier, got %s", p.curToken.Type)
			p.appendError(p.curToken, msg)
			stop := p.synchronizeToTokenTypes(token.COMMA, token.RBRACE, token.SEMICOLON)
			if stop == token.COMMA {
				continue
			}
			break
		}

		fieldNameStart := p.startMark()
		fieldName := &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}
		p.recordRange(fieldName, fieldNameStart)
		field := &ast.StructFieldValue{Name: fieldName}

		if !p.expectPeek(token.COLON) {
			stop := p.synchronizeToTokenTypes(token.COMMA, token.RBRACE, token.SEMICOLON)
			if stop == token.COMMA {
				continue
			}
			break
		}

		p.nextToken()
		field.Value = p.parseExpression(LOWEST)
		if field.Value != nil {
			lit.Fields = append(lit.Fields, field)
		} else {
			stop := p.synchronizeToTokenTypes(token.COMMA, token.RBRACE, token.SEMICOLON)
			if stop == token.COMMA {
				continue
			}
			break
		}

		if !p.peekTokenIs(token.RBRACE) && !p.expectPeek(token.COMMA) {
			stop := p.synchronizeToTokenTypes(token.COMMA, token.RBRACE, token.SEMICOLON)
			if stop == token.COMMA {
				continue
			}
			break
		}
	}

	if !p.expectPeek(token.RBRACE) {
		p.recordRange(lit, start)
		return lit
	}

	p.recordRange(lit, start)
	return lit
}
