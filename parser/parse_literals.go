package parser

import (
	"fmt"
	"mutant/ast"
	"mutant/token"
	"strconv"
)

func (p *Parser) parseFloatLiteral() ast.Expression {
	start := p.startMark()
	lit := &ast.FloatLiteral{Token: p.curToken}
	value, err := strconv.ParseFloat(p.curToken.Literal, 64)

	if err != nil {
		msg := fmt.Sprintf("could not parse %q as float", p.curToken.Literal)
		p.appendError(p.curToken, msg)
	}

	lit.Value = value

	p.recordRange(lit, start)
	return lit
}

func (p *Parser) parseIntegerLiteral() ast.Expression {
	// defer untrace(trace("parseIntegerLiteral"))

	start := p.startMark()
	lit := &ast.IntegerLiteral{Token: p.curToken}
	value, err := strconv.ParseInt(p.curToken.Literal, 0, 64)

	if err != nil {
		msg := fmt.Sprintf("could not parse %q as integer", p.curToken.Literal)
		p.appendError(p.curToken, msg)
		return nil
	}

	lit.Value = value

	p.recordRange(lit, start)
	return lit
}

func (p *Parser) parseStringLiteral() ast.Expression {
	start := p.startMark()
	lit := &ast.StringLiteral{Token: p.curToken, Value: p.curToken.Literal}
	p.recordRange(lit, start)
	return lit
}

func (p *Parser) parseFunctionLiteral() ast.Expression {
	start := p.startMark()
	lit := &ast.FunctionLiteral{Token: p.curToken}

	if !p.expectPeek(token.LPAREN) {
		return nil
	}

	lit.Parameters = p.parseFunctionParameters()

	if !p.expectPeek(token.LBRACE) {
		return nil
	}

	lit.Body = p.parseBlockStatement()

	p.recordRange(lit, start)
	return lit
}

func (p *Parser) parseArrayLiteral() ast.Expression {
	start := p.startMark()
	array := &ast.ArrayLiteral{Token: p.curToken}
	array.Elements = p.parseExpressionList(token.RSQUARE)
	p.recordRange(array, start)
	return array
}

func (p *Parser) parseHashLiteral() ast.Expression {
	start := p.startMark()
	hash := &ast.HashLiteral{Token: p.curToken}
	hash.Pairs = make(map[ast.Expression]ast.Expression)

	for !p.peekTokenIs(token.RBRACE) && !p.peekTokenIs(token.EOF) {
		p.nextToken()
		key := p.parseExpression(LOWEST)
		if key == nil {
			stop := p.synchronizeToTokenTypes(token.COMMA, token.RBRACE, token.SEMICOLON)
			if stop == token.COMMA {
				continue
			}
			break
		}

		if !p.expectPeek(token.COLON) {
			stop := p.synchronizeToTokenTypes(token.COMMA, token.RBRACE, token.SEMICOLON)
			if stop == token.COMMA {
				continue
			}
			break
		}

		p.nextToken()
		value := p.parseExpression(LOWEST)
		if value != nil {
			hash.Pairs[key] = value
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
		p.recordRange(hash, start)
		return hash
	}

	p.recordRange(hash, start)
	return hash
}

func (p *Parser) parseMacroLiteral() ast.Expression {
	start := p.startMark()
	lit := &ast.MacroLiteral{Token: p.curToken}

	if !p.expectPeek(token.LPAREN) {
		return nil
	}

	lit.Parameters = p.parseFunctionParameters()

	if !p.expectPeek(token.LBRACE) {
		return nil
	}

	lit.Body = p.parseBlockStatement()

	p.recordRange(lit, start)
	return lit
}
