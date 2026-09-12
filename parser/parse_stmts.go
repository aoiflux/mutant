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
	p.blockDepth++
	defer func() { p.blockDepth-- }()
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
	case token.SEMICOLON:
		// An empty statement: a `;` terminating nothing, as in `let x = 1;;`.
		// Previously this fell through to expression parsing and produced a
		// hard "no prefix parse function" error. Report it as recoverable and
		// drop it instead, so the tree stays clean and the formatter can
		// remove the stray token simply by not re-emitting it.
		p.recordRedundantSemicolon(p.curToken)
		return nil
	case token.LET:
		return p.parseLetStatement()
	case token.RETURN:
		return p.parseReturnStatement()
	case token.FOR:
		return p.parseForOrForIn()
	case token.WHILE:
		return p.parseWhileStatement()
	case token.BREAK:
		return p.parseBreakStatement()
	case token.CONTINUE:
		return p.parseContinueStatement()
	case token.STRUCT:
		return p.parseStructStatement()
	case token.ENUM:
		return p.parseEnumStatement()
	case token.IMPORT:
		return p.parseImportStatement()
	default:
		return p.parseExpressionStatement()
	}
}

func (p *Parser) parseBreakStatement() *ast.BreakStatement {
	start := p.startMark()
	stmt := &ast.BreakStatement{Token: p.curToken}
	p.consumeStatementTerminator(stmt)
	p.recordRange(stmt, start)
	return stmt
}

func (p *Parser) parseContinueStatement() *ast.ContinueStatement {
	start := p.startMark()
	stmt := &ast.ContinueStatement{Token: p.curToken}
	p.consumeStatementTerminator(stmt)
	p.recordRange(stmt, start)
	return stmt
}

// parseImportStatement parses `import "path.mut";` and `import ns "path.mut";`.
//
// The path is required to be a string literal rather than an expression. An
// import is resolved and compiled before the program runs, so there is no point
// at which a computed path could be evaluated -- accepting one would mean
// accepting source that can never work.
//
// For the same reason an import is only legal at the top level of a file. The
// module graph is walked and linked before a single instruction executes, so
// an import nested in a function body or loop would be loaded regardless of
// whether control ever reached it -- a statement whose position implies a
// conditionality the language cannot honour.
func (p *Parser) parseImportStatement() *ast.ImportStatement {
	if p.blockDepth > 0 {
		p.appendError(p.curToken, "import is only allowed at the top level of a file, not inside a block")
		return nil
	}

	start := p.startMark()
	stmt := &ast.ImportStatement{Token: p.curToken}

	if p.peekTokenIs(token.IDENT) {
		p.nextToken()
		aliasStart := p.startMark()
		stmt.Alias = &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}
		p.recordRange(stmt.Alias, aliasStart)
	}

	if !p.peekTokenIs(token.STRING) {
		msg := fmt.Sprintf("expected an import path as a quoted string, got %s", p.peekToken.Type)
		p.appendError(p.peekToken, msg)
		return nil
	}
	p.nextToken()

	pathStart := p.startMark()
	stmt.Path = &ast.StringLiteral{Token: p.curToken, Value: p.curToken.Literal}
	p.recordRange(stmt.Path, pathStart)

	p.consumeStatementTerminator(stmt)
	p.recordRange(stmt, start)
	return stmt
}

// parseWhileStatement parses `while (cond) { ... }`.
//
// The parentheses are required, matching `for` and `if`, so that the condition
// has an unambiguous end and a body brace cannot be mistaken for a hash
// literal in the condition.
func (p *Parser) parseWhileStatement() *ast.WhileStatement {
	start := p.startMark()
	stmt := &ast.WhileStatement{Token: p.curToken}

	if !p.expectPeek(token.LPAREN) {
		return nil
	}

	p.nextToken()
	if p.curTokenIs(token.RPAREN) {
		// `while ()` is refused rather than treated as `while (true)`. An
		// endless loop should have to say so.
		p.appendError(p.curToken, "while needs a condition; write while (true) for an endless loop")
		return nil
	}

	stmt.Condition = p.parseExpression(LOWEST)
	if !p.expectPeek(token.RPAREN) {
		return nil
	}

	if !p.expectPeek(token.LBRACE) {
		return nil
	}

	stmt.Body = p.parseBlockStatement()
	p.recordRange(stmt, start)
	return stmt
}

// parseForOrForIn decides which of the two loops spelled `for (` this is.
//
// The header forms are distinguishable at the first token after the paren:
// `for (v in`, `for (k, v in` and nothing else begins with an identifier
// followed by `in` or `,`. A C-style header's init section is a let statement
// or an expression, and neither can be a bare identifier followed by a comma --
// there is no comma operator -- so committing to the for-in path on that lookahead
// cannot mis-parse a valid classic header.
func (p *Parser) parseForOrForIn() ast.Statement {
	start := p.startMark()
	forToken := p.curToken

	if !p.expectPeek(token.LPAREN) {
		return nil
	}
	p.nextToken()

	if p.curTokenIs(token.IDENT) && (p.peekTokenIs(token.IN) || p.peekTokenIs(token.COMMA)) {
		return p.parseForInStatement(start, forToken)
	}
	return p.parseForStatement(start, forToken)
}

// parseForInStatement parses the header from its first binding name onward;
// `for (` has already been consumed.
func (p *Parser) parseForInStatement(start token.Position, forToken token.Token) *ast.ForInStatement {
	stmt := &ast.ForInStatement{Token: forToken}

	firstStart := p.startMark()
	first := &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}
	p.recordRange(first, firstStart)

	if p.peekTokenIs(token.COMMA) {
		p.nextToken()
		if !p.expectPeek(token.IDENT) {
			return nil
		}
		secondStart := p.startMark()
		second := &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}
		p.recordRange(second, secondStart)
		stmt.Key, stmt.Value = first, second
	} else {
		stmt.Value = first
	}

	if !p.expectPeek(token.IN) {
		return nil
	}

	p.nextToken()
	if p.curTokenIs(token.RPAREN) {
		p.appendError(p.curToken, "for ... in needs something to iterate over")
		return nil
	}

	stmt.Iterable = p.parseExpression(LOWEST)
	if !p.expectPeek(token.RPAREN) {
		return nil
	}
	if !p.expectPeek(token.LBRACE) {
		return nil
	}

	stmt.Body = p.parseBlockStatement()
	p.recordRange(stmt, start)
	return stmt
}

// parseForStatement parses the C-style header from its init section onward;
// `for (` has already been consumed.
func (p *Parser) parseForStatement(start token.Position, forToken token.Token) *ast.ForStatement {
	stmt := &ast.ForStatement{Token: forToken}

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

	p.consumeStatementTerminator(stmt)
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

	p.consumeStatementTerminator(stmt)

	p.recordRange(stmt, start)
	return stmt
}
