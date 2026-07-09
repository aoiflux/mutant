package parser

import (
	"fmt"
	"mutant/ast"
	"mutant/token"
)

func (p *Parser) parseBlockStatement() *ast.BlockStatement {
	block := &ast.BlockStatement{Token: p.curToken}
	block.Statements = []ast.Statement{}
	p.nextToken()
	for !p.curTokenIs(token.RBRACE) && !p.curTokenIs(token.EOF) {
		stmt := p.parseStatement()
		if (stmt.String() != "") && (stmt.TokenLiteral() != "") {
			block.Statements = append(block.Statements, stmt)
		}
		p.nextToken()
	}
	return block
}

func (p *Parser) parseStatement() ast.Statement {
	switch p.curToken.Type {
	case token.LET:
		return p.parseLetStatement()
	case token.RETURN:
		return p.parseReturnStatement()
	case token.FOR:
		return p.parseForStatement()
	case token.BREAK:
		return p.parseBreakStatement()
	case token.CONTINUE:
		return p.parseContinueStatement()
	case token.STRUCT:
		return p.parseStructStatement()
	case token.ENUM:
		return p.parseEnumStatement()
	default:
		return p.parseExpressionStatement()
	}
}

func (p *Parser) parseBreakStatement() *ast.BreakStatement {
	stmt := &ast.BreakStatement{Token: p.curToken}
	if p.peekTokenIs(token.SEMICOLON) {
		p.nextToken()
	}
	return stmt
}

func (p *Parser) parseContinueStatement() *ast.ContinueStatement {
	stmt := &ast.ContinueStatement{Token: p.curToken}
	if p.peekTokenIs(token.SEMICOLON) {
		p.nextToken()
	}
	return stmt
}

func (p *Parser) parseForStatement() *ast.ForStatement {
	stmt := &ast.ForStatement{Token: p.curToken}

	if !p.expectPeek(token.LPAREN) {
		return nil
	}

	p.nextToken()
	if !p.curTokenIs(token.SEMICOLON) {
		switch p.curToken.Type {
		case token.LET:
			stmt.Init = p.parseLetStatement()
		default:
			stmt.Init = p.parseExpressionStatement()
		}
	}

	if !p.curTokenIs(token.SEMICOLON) {
		msg := fmt.Sprintf("expected token %s in for init section, got %s", token.SEMICOLON, p.curToken.Type)
		p.errors = append(p.errors, msg)
		return nil
	}

	p.nextToken()
	if !p.curTokenIs(token.SEMICOLON) {
		stmt.Condition = p.parseExpression(LOWEST)
		if !p.expectPeek(token.SEMICOLON) {
			return nil
		}
	}

	p.nextToken()
	if !p.curTokenIs(token.RPAREN) {
		stmt.Post = p.parseExpression(LOWEST)
		if !p.expectPeek(token.RPAREN) {
			return nil
		}
	}

	if !p.expectPeek(token.LBRACE) {
		return nil
	}

	stmt.Body = p.parseBlockStatement()
	return stmt
}

func (p *Parser) parseStructStatement() *ast.StructStatement {
	stmt := &ast.StructStatement{Token: p.curToken, Fields: []*ast.Identifier{}}

	if !p.expectPeek(token.IDENT) {
		return nil
	}

	stmt.Name = &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}

	if !p.expectPeek(token.LBRACE) {
		return nil
	}

	for !p.peekTokenIs(token.RBRACE) {
		p.nextToken()
		if !p.curTokenIs(token.IDENT) {
			msg := fmt.Sprintf("expected struct field identifier, got %s", p.curToken.Type)
			p.errors = append(p.errors, msg)
			return nil
		}

		field := &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}
		stmt.Fields = append(stmt.Fields, field)

		if p.peekTokenIs(token.SEMICOLON) || p.peekTokenIs(token.COMMA) {
			p.nextToken()
		} else if !p.peekTokenIs(token.RBRACE) {
			msg := fmt.Sprintf("expected ';' or '}' in struct declaration, got %s", p.peekToken.Type)
			p.errors = append(p.errors, msg)
			return nil
		}
	}

	if !p.expectPeek(token.RBRACE) {
		return nil
	}

	if p.peekTokenIs(token.SEMICOLON) {
		p.nextToken()
	}

	return stmt
}

func (p *Parser) parseEnumStatement() *ast.EnumStatement {
	stmt := &ast.EnumStatement{Token: p.curToken, Variants: []*ast.Identifier{}}

	if !p.expectPeek(token.IDENT) {
		return nil
	}

	stmt.Name = &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}

	if !p.expectPeek(token.LBRACE) {
		return nil
	}

	for !p.peekTokenIs(token.RBRACE) {
		p.nextToken()
		if !p.curTokenIs(token.IDENT) {
			msg := fmt.Sprintf("expected enum variant identifier, got %s", p.curToken.Type)
			p.errors = append(p.errors, msg)
			return nil
		}

		variant := &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}
		stmt.Variants = append(stmt.Variants, variant)

		if p.peekTokenIs(token.COMMA) || p.peekTokenIs(token.SEMICOLON) {
			p.nextToken()
		} else if !p.peekTokenIs(token.RBRACE) {
			msg := fmt.Sprintf("expected ',' or '}' in enum declaration, got %s", p.peekToken.Type)
			p.errors = append(p.errors, msg)
			return nil
		}
	}

	if !p.expectPeek(token.RBRACE) {
		return nil
	}

	if p.peekTokenIs(token.SEMICOLON) {
		p.nextToken()
	}

	return stmt
}

func (p *Parser) parseReturnStatement() *ast.ReturnStatement {
	stmt := &ast.ReturnStatement{Token: p.curToken}
	p.nextToken()

	if p.curTokenIs(token.SEMICOLON) {
		return stmt
	}

	first := p.parseExpression(LOWEST)
	if first != nil {
		stmt.ReturnValues = append(stmt.ReturnValues, first)
		stmt.ReturnValue = first
	}

	for p.peekTokenIs(token.COMMA) {
		p.nextToken()
		p.nextToken()

		nextExpr := p.parseExpression(LOWEST)
		if nextExpr != nil {
			stmt.ReturnValues = append(stmt.ReturnValues, nextExpr)
		}
	}

	if p.peekTokenIs(token.SEMICOLON) {
		p.nextToken()
	}
	return stmt
}

func (p *Parser) parseLetStatement() *ast.LetStatement {
	stmt := &ast.LetStatement{Token: p.curToken}
	if !p.expectPeek(token.IDENT) {
		return nil
	}

	firstName := &ast.Identifier{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}
	stmt.Name = firstName
	stmt.Names = []*ast.Identifier{firstName}

	for p.peekTokenIs(token.COMMA) {
		p.nextToken()
		if !p.expectPeek(token.IDENT) {
			return nil
		}
		stmt.Names = append(stmt.Names, &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal})
	}

	if !p.expectPeek(token.ASSIGN) {
		return nil
	}
	p.nextToken()

	stmt.Value = p.parseExpression(LOWEST)

	if fl, ok := stmt.Value.(*ast.FunctionLiteral); ok {
		fl.Name = stmt.Name.Value
	}

	if !p.curTokenIs(token.SEMICOLON) {
		p.nextToken()
	}

	return stmt
}
