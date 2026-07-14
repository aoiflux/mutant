package parser

import (
	"fmt"
	"mutant/ast"
	"mutant/token"
	"reflect"
)

func (p *Parser) parseBlockStatement() *ast.BlockStatement {
	start := p.startMark()
	block := &ast.BlockStatement{Token: p.curToken}
	block.Statements = []ast.Statement{}
	p.nextToken()
	for !p.curTokenIs(token.RBRACE) && !p.curTokenIs(token.EOF) {
		beforeErrCount := len(p.errors)
		stmt := p.parseStatement()
		if shouldAppendStatement(stmt) {
			block.Statements = append(block.Statements, stmt)
		}
		if len(p.errors) > beforeErrCount {
			p.synchronizeToStatementBoundary()
		}
		p.nextToken()
	}
	p.recordRange(block, start)
	return block
}

func shouldAppendStatement(stmt ast.Statement) bool {
	if isNilStatement(stmt) {
		return false
	}

	if expStmt, ok := stmt.(*ast.ExpressionStatement); ok {
		if expStmt == nil || expStmt.Expression == nil {
			return false
		}
	}

	return true
}

func isNilStatement(stmt ast.Statement) bool {
	if stmt == nil {
		return true
	}
	v := reflect.ValueOf(stmt)
	if v.Kind() == reflect.Ptr && v.IsNil() {
		return true
	}
	return false
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
	start := p.startMark()
	stmt := &ast.BreakStatement{Token: p.curToken}
	if p.peekTokenIs(token.SEMICOLON) {
		p.nextToken()
	}
	p.recordRange(stmt, start)
	return stmt
}

func (p *Parser) parseContinueStatement() *ast.ContinueStatement {
	start := p.startMark()
	stmt := &ast.ContinueStatement{Token: p.curToken}
	if p.peekTokenIs(token.SEMICOLON) {
		p.nextToken()
	}
	p.recordRange(stmt, start)
	return stmt
}

func (p *Parser) parseForStatement() *ast.ForStatement {
	start := p.startMark()
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
		p.appendError(p.curToken, msg)
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
	p.recordRange(stmt, start)
	return stmt
}

func (p *Parser) parseStructStatement() *ast.StructStatement {
	start := p.startMark()
	stmt := &ast.StructStatement{Token: p.curToken, Fields: []*ast.Identifier{}}

	if !p.expectPeek(token.IDENT) {
		return nil
	}

	nameStart := p.startMark()
	stmt.Name = &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}
	p.recordRange(stmt.Name, nameStart)

	if !p.expectPeek(token.LBRACE) {
		return nil
	}

	for !p.peekTokenIs(token.RBRACE) {
		p.nextToken()
		if !p.curTokenIs(token.IDENT) {
			msg := fmt.Sprintf("expected struct field identifier, got %s", p.curToken.Type)
			p.appendError(p.curToken, msg)
			return nil
		}

		fieldStart := p.startMark()
		field := &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}
		p.recordRange(field, fieldStart)
		stmt.Fields = append(stmt.Fields, field)

		if p.peekTokenIs(token.SEMICOLON) || p.peekTokenIs(token.COMMA) {
			p.nextToken()
		} else if !p.peekTokenIs(token.RBRACE) {
			msg := fmt.Sprintf("expected ';' or '}' in struct declaration, got %s", p.peekToken.Type)
			p.appendError(p.peekToken, msg)
			return nil
		}
	}

	if !p.expectPeek(token.RBRACE) {
		return nil
	}

	if p.peekTokenIs(token.SEMICOLON) {
		p.nextToken()
	}

	p.recordRange(stmt, start)
	return stmt
}

func (p *Parser) parseEnumStatement() *ast.EnumStatement {
	start := p.startMark()
	stmt := &ast.EnumStatement{Token: p.curToken, Variants: []*ast.Identifier{}}

	if !p.expectPeek(token.IDENT) {
		return nil
	}

	nameStart := p.startMark()
	stmt.Name = &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}
	p.recordRange(stmt.Name, nameStart)

	if !p.expectPeek(token.LBRACE) {
		return nil
	}

	for !p.peekTokenIs(token.RBRACE) {
		p.nextToken()
		if !p.curTokenIs(token.IDENT) {
			msg := fmt.Sprintf("expected enum variant identifier, got %s", p.curToken.Type)
			p.appendError(p.curToken, msg)
			return nil
		}

		varStart := p.startMark()
		variant := &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}
		p.recordRange(variant, varStart)
		stmt.Variants = append(stmt.Variants, variant)

		if p.peekTokenIs(token.COMMA) || p.peekTokenIs(token.SEMICOLON) {
			p.nextToken()
		} else if !p.peekTokenIs(token.RBRACE) {
			msg := fmt.Sprintf("expected ',' or '}' in enum declaration, got %s", p.peekToken.Type)
			p.appendError(p.peekToken, msg)
			return nil
		}
	}

	if !p.expectPeek(token.RBRACE) {
		return nil
	}

	if p.peekTokenIs(token.SEMICOLON) {
		p.nextToken()
	}

	p.recordRange(stmt, start)
	return stmt
}

func (p *Parser) parseReturnStatement() *ast.ReturnStatement {
	start := p.startMark()
	stmt := &ast.ReturnStatement{Token: p.curToken}
	p.nextToken()

	if p.curTokenIs(token.SEMICOLON) {
		p.recordRange(stmt, start)
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
	p.recordRange(stmt, start)
	return stmt
}

func (p *Parser) parseLetStatement() *ast.LetStatement {
	start := p.startMark()
	stmt := &ast.LetStatement{Token: p.curToken}
	if !p.expectPeek(token.IDENT) {
		return nil
	}

	firstNameStart := p.startMark()
	firstName := &ast.Identifier{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}
	p.recordRange(firstName, firstNameStart)
	stmt.Name = firstName
	stmt.Names = []*ast.Identifier{firstName}

	for p.peekTokenIs(token.COMMA) {
		p.nextToken()
		if !p.expectPeek(token.IDENT) {
			return nil
		}
		nameStart := p.startMark()
		name := &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}
		p.recordRange(name, nameStart)
		stmt.Names = append(stmt.Names, name)
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

	p.recordRange(stmt, start)
	return stmt
}
