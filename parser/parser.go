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
	LOGIC_OR
	LOGIC_AND
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
	token.OR:         LOGIC_OR,
	token.AND:        LOGIC_AND,
	token.EQUALITY:   EQUALS,
	token.INEQUALITY: EQUALS,
	token.LT:         LESSGREATER,
	token.GT:         LESSGREATER,
	token.LTE:        LESSGREATER,
	token.GTE:        LESSGREATER,
	token.PLUS:       SUM,
	token.MINUS:      SUM,
	token.FSLASH:     PRODUCT,
	token.ASTERISK:   PRODUCT,
	token.MODULO:     PRODUCT,
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

// RecoverableKind classifies a problem the parser could parse through.
type RecoverableKind string

const (
	// MissingSemicolon marks a statement that requires a `;` terminator but
	// does not have one. Its Range is zero-width and sits immediately after
	// the statement's final token, so it doubles as the insertion point for
	// a formatter edit or an LSP quick fix.
	MissingSemicolon RecoverableKind = "missing-semicolon"

	// RedundantSemicolon marks a `;` that terminates nothing — an empty
	// statement such as the second `;` in `let x = 1;;`. Its Range covers
	// the stray token so it can be deleted verbatim.
	RedundantSemicolon RecoverableKind = "redundant-semicolon"
)

// RecoverableError is a parse problem that does not prevent the parser from
// producing a complete, usable AST.
//
// Mutant mandates semicolons but the formatter is required to repair them,
// which is only possible if the tree survives the mistake. Recoverable
// errors are therefore kept out of Errors and TypedErrors: the CLI, REPL,
// compiler and evaluator continue to reject only genuinely unparseable
// input, while tooling that opts in via Recoverables can offer diagnostics
// and fixes.
type RecoverableError struct {
	ParseError
	Kind RecoverableKind
}

type Parser struct {
	l              *lexer.Lexer
	curToken       token.Token
	peekToken      token.Token
	errors         []string
	typedErrors    []ParseError
	recoverables   []RecoverableError
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
	p.registerInfix(token.LTE, p.parseInfixExpression)
	p.registerInfix(token.GTE, p.parseInfixExpression)
	p.registerInfix(token.MODULO, p.parseInfixExpression)
	p.registerInfix(token.AND, p.parseInfixExpression)
	p.registerInfix(token.OR, p.parseInfixExpression)
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

	// The lexer has now been driven through EOF, so its comment trivia is
	// complete and can be published for the formatter.
	program.Comments = p.l.Comments()

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
// Recoverables returns problems the parser repaired its way past, in source
// order. It is deliberately separate from Errors and TypedErrors so that
// existing consumers keep their pass/fail behaviour unchanged.
func (p *Parser) Recoverables() []RecoverableError { return p.recoverables }

// consumeStatementTerminator settles the `;` at the end of stmt.
//
// It is called with curToken on the statement's final token. When a
// semicolon follows it is consumed, leaving curToken on the `;` exactly as
// the previous hand-rolled checks did. When one is required but absent, a
// recoverable error is recorded and the cursor is left in place — crucially
// *without* advancing, so the next statement starts where it should. The
// older `if !p.curTokenIs(SEMICOLON) { p.nextToken() }` idiom swallowed the
// first token of the following statement whenever a semicolon was missing.
func (p *Parser) consumeStatementTerminator(stmt ast.Statement) {
	if p.peekTokenIs(token.SEMICOLON) {
		p.nextToken()
		return
	}

	if stmt == nil || !stmt.RequiresSemicolon() {
		return
	}

	p.recordMissingSemicolon(p.curToken)
}

// recordMissingSemicolon notes that the statement ending at tok needs a `;`.
// The range is zero-width at tok's end so consumers can treat it directly as
// an insertion point.
func (p *Parser) recordMissingSemicolon(tok token.Token) {
	p.recoverables = append(p.recoverables, RecoverableError{
		ParseError: ParseError{
			Msg:   "missing ';' at end of statement",
			Range: ast.Range{Start: tok.End, End: tok.End},
		},
		Kind: MissingSemicolon,
	})
}

// recordRedundantSemicolon notes a `;` that terminates no statement.
func (p *Parser) recordRedundantSemicolon(tok token.Token) {
	p.recoverables = append(p.recoverables, RecoverableError{
		ParseError: ParseError{
			Msg:   "redundant ';'",
			Range: ast.Range{Start: tok.Start, End: tok.End},
		},
		Kind: RedundantSemicolon,
	})
}

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
