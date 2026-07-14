package parser

import (
	"fmt"
	"mutant/ast"
	"mutant/lexer"
	"mutant/token"
)

const (
	_ int = iota
	LOWEST
	ASSIGNMENT
	EQUALS
	LESSGREATER
	SUM
	PRODUCT
	PREFIX
	CALL
	INDEX
	FIELD
)

var precedences = map[token.TokenType]int{
	token.ASSIGN:     ASSIGNMENT,
	token.EQUALITY:   EQUALS,
	token.INEQUALITY: EQUALS,
	token.LT:         LESSGREATER,
	token.GT:         LESSGREATER,
	token.PLUS:       SUM,
	token.MINUS:      SUM,
	token.FSLASH:     PRODUCT,
	token.ASTERISK:   PRODUCT,
	token.LPAREN:     CALL,
	token.LSQUARE:    INDEX,
	token.DOT:        FIELD,
	token.LBRACE:     CALL,
}

type (
	prefixParseFn func() ast.Expression
	infixParseFn  func(ast.Expression) ast.Expression
)

// ParseError is a parser error annotated with a source range. Callers that
// need to render diagnostics (the language server, IDE integrations) should
// use TypedErrors. The plain Errors slice is preserved for backwards
// compatibility with the CLI and REPL.
type ParseError struct {
	Msg   string
	Range ast.Range
}

type Parser struct {
	l              *lexer.Lexer
	curToken       token.Token
	peekToken      token.Token
	errors         []string
	typedErrors    []ParseError
	nodeRanges     map[ast.Node]ast.Range
	prefixParseFns map[token.TokenType]prefixParseFn
	infixParseFns  map[token.TokenType]infixParseFn
}

func New(l *lexer.Lexer) *Parser {
	p := &Parser{l: l, errors: []string{}}

	p.prefixParseFns = make(map[token.TokenType]prefixParseFn)
	p.registerPrefix(token.IDENT, p.parseIdentifier)
	p.registerPrefix(token.INT, p.parseIntegerLiteral)
	p.registerPrefix(token.FLOAT, p.parseFloatLiteral)
	p.registerPrefix(token.BANG, p.parsePrefixExpression)
	p.registerPrefix(token.MINUS, p.parsePrefixExpression)
	p.registerPrefix(token.TRUE, p.parseBoolean)
	p.registerPrefix(token.FALSE, p.parseBoolean)
	p.registerPrefix(token.LPAREN, p.parseGroupedExpression)
	p.registerPrefix(token.IF, p.parseIfExpression)
	p.registerPrefix(token.FUNCTION, p.parseFunctionLiteral)
	p.registerPrefix(token.STRING, p.parseStringLiteral)
	p.registerPrefix(token.LSQUARE, p.parseArrayLiteral)

	p.infixParseFns = make(map[token.TokenType]infixParseFn)
	p.registerInfix(token.PLUS, p.parseInfixExpression)
	p.registerInfix(token.MINUS, p.parseInfixExpression)
	p.registerInfix(token.FSLASH, p.parseInfixExpression)
	p.registerInfix(token.ASTERISK, p.parseInfixExpression)
	p.registerInfix(token.EQUALITY, p.parseInfixExpression)
	p.registerInfix(token.INEQUALITY, p.parseInfixExpression)
	p.registerInfix(token.LT, p.parseInfixExpression)
	p.registerInfix(token.GT, p.parseInfixExpression)
	p.registerInfix(token.ASSIGN, p.parseAssignExpression)
	p.registerInfix(token.LPAREN, p.parseCallExpression)
	p.registerInfix(token.LSQUARE, p.parseIndexExpression)
	p.registerInfix(token.DOT, p.parseFieldExpression)
	p.registerInfix(token.LBRACE, p.parseStructLiteralExpression)
	p.registerPrefix(token.LBRACE, p.parseHashLiteral)
	p.registerPrefix(token.MACRO, p.parseMacroLiteral)

	p.nextToken()
	p.nextToken()

	return p
}

func (p *Parser) nextToken() {
	p.curToken = p.peekToken
	p.peekToken = p.l.NextToken()
}

func (p *Parser) ParseProgram() *ast.Program {
	program := &ast.Program{}
	program.Statements = []ast.Statement{}

	for !p.curTokenIs(token.EOF) {
		beforeErrCount := len(p.errors)
		stmt := p.parseStatement()
		if shouldAppendStatement(stmt) {
			program.Statements = append(program.Statements, stmt)
		}
		if len(p.errors) > beforeErrCount {
			p.synchronizeToStatementBoundary()
		}
		p.nextToken()
	}

	// Publish the collected node ranges on the program so the LSP and
	// other tooling can look up positions without touching individual
	// AST node structs. When no ranges were recorded (which should never
	// happen in practice) we leave the map nil so RangeOf stays cheap.
	if len(p.nodeRanges) > 0 {
		program.NodePositions = p.nodeRanges
	}
	return program
}

func (p *Parser) synchronizeToStatementBoundary() {
	if p == nil {
		return
	}

	for !p.curTokenIs(token.EOF) {
		if p.curTokenIs(token.SEMICOLON) || p.curTokenIs(token.RBRACE) {
			return
		}
		p.nextToken()
	}
}

func (p *Parser) synchronizeToTokenTypes(stop ...token.TokenType) token.TokenType {
	if p == nil {
		return token.EOF
	}

	if len(stop) == 0 {
		return token.EOF
	}

	stopSet := make(map[token.TokenType]struct{}, len(stop))
	for _, t := range stop {
		stopSet[t] = struct{}{}
	}

	for !p.curTokenIs(token.EOF) {
		if _, ok := stopSet[p.curToken.Type]; ok {
			return p.curToken.Type
		}
		p.nextToken()
	}

	return token.EOF
}

func (p *Parser) Errors() []string { return p.errors }

// TypedErrors returns the parser's accumulated errors annotated with source
// ranges. It complements Errors, which returns plain strings for the CLI
// and REPL.
func (p *Parser) TypedErrors() []ParseError { return p.typedErrors }

// startMark captures the current token's start position. Callers use it at
// the top of a parse function to remember where a node begins before it is
// fully constructed. Pair with recordRange at each successful return point.
func (p *Parser) startMark() token.Position { return p.curToken.Start }

// recordRange associates a source range with a node. start comes from
// startMark; the end is derived from the last consumed token (curToken.End),
// which under Pratt parsing points just past the tail of the just-parsed
// construct. Nil nodes are ignored so instrumented parse helpers can call
// this unconditionally even on error paths.
func (p *Parser) recordRange(n ast.Node, start token.Position) {
	if n == nil {
		return
	}
	if p.nodeRanges == nil {
		p.nodeRanges = make(map[ast.Node]ast.Range)
	}
	p.nodeRanges[n] = ast.Range{Start: start, End: p.curToken.End}
}

// appendError records both a legacy string error and a range-annotated
// ParseError for the same problem. The range is derived from tok so that
// LSP clients can highlight the offending token precisely.
func (p *Parser) appendError(tok token.Token, msg string) {
	p.errors = append(p.errors, msg)
	p.typedErrors = append(p.typedErrors, ParseError{
		Msg:   msg,
		Range: ast.Range{Start: tok.Start, End: tok.End},
	})
}

func (p *Parser) parseIdentifier() ast.Expression {
	start := p.startMark()
	ident := &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}
	p.recordRange(ident, start)
	return ident
}

func (p *Parser) parseBoolean() ast.Expression {
	start := p.startMark()
	b := &ast.Boolean{Token: p.curToken, Value: p.curTokenIs(token.TRUE)}
	p.recordRange(b, start)
	return b
}

func (p *Parser) parseFunctionParameters() []*ast.Identifier {
	identifiers := []*ast.Identifier{}

	if p.peekTokenIs(token.RPAREN) {
		p.nextToken()
		return identifiers
	}

	p.nextToken()

	identStart := p.startMark()
	ident := &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}
	p.recordRange(ident, identStart)
	identifiers = append(identifiers, ident)

	for p.peekTokenIs(token.COMMA) {
		p.nextToken()
		p.nextToken()

		nextStart := p.startMark()
		ident := &ast.Identifier{Token: p.curToken, Value: p.curToken.Literal}
		p.recordRange(ident, nextStart)
		identifiers = append(identifiers, ident)
	}

	if !p.expectPeek(token.RPAREN) {
		return nil
	}

	return identifiers
}

func (p *Parser) parseCallArguments() []ast.Expression {
	args := []ast.Expression{}

	if p.peekTokenIs(token.RPAREN) {
		p.nextToken()
		return args
	}

	p.nextToken()
	args = append(args, p.parseExpression(LOWEST))

	for p.peekTokenIs(token.COMMA) {
		p.nextToken()
		p.nextToken()
		args = append(args, p.parseExpression(LOWEST))
	}

	if !p.expectPeek(token.RPAREN) {
		return nil
	}

	return args
}

func (p *Parser) expectPeek(tokenType token.TokenType) bool {
	if p.peekTokenIs(tokenType) {
		p.nextToken()
		return true
	}
	p.peekError(tokenType)
	return false
}

func (p *Parser) peekTokenIs(tokenType token.TokenType) bool { return p.peekToken.Type == tokenType }
func (p *Parser) curTokenIs(tokenType token.TokenType) bool  { return p.curToken.Type == tokenType }
func (p *Parser) peekError(t token.TokenType) {
	msg := fmt.Sprintf("expected next token to be %s, but got %s instead", t, p.peekToken.Type)
	p.appendError(p.peekToken, msg)
}

func (p *Parser) peekPrecedence() int {
	if prec, ok := precedences[p.peekToken.Type]; ok {
		return prec
	}
	return LOWEST
}

func (p *Parser) curPrecedence() int {
	if prec, ok := precedences[p.curToken.Type]; ok {
		return prec
	}
	return LOWEST
}

func (p *Parser) registerPrefix(tokenType token.TokenType, fn prefixParseFn) {
	p.prefixParseFns[tokenType] = fn
}

func (p *Parser) registerInfix(tokenType token.TokenType, fn infixParseFn) {
	p.infixParseFns[tokenType] = fn
}

func (p *Parser) notPrefixParseFnError(t token.TokenType) {
	msg := fmt.Sprintf("no prefix parse function for %s found", t)
	p.appendError(p.curToken, msg)
}
