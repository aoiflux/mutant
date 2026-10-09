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
	token.ASSIGN:          ASSIGNMENT,
	token.PLUS_ASSIGN:     ASSIGNMENT,
	token.MINUS_ASSIGN:    ASSIGNMENT,
	token.ASTERISK_ASSIGN: ASSIGNMENT,
	token.SLASH_ASSIGN:    ASSIGNMENT,
	token.MODULO_ASSIGN:   ASSIGNMENT,
	token.AND_ASSIGN:      ASSIGNMENT,
	token.OR_ASSIGN:       ASSIGNMENT,
	token.XOR_ASSIGN:      ASSIGNMENT,
	token.SHL_ASSIGN:      ASSIGNMENT,
	token.SHR_ASSIGN:      ASSIGNMENT,
	token.OR:              LOGIC_OR,
	token.AND:             LOGIC_AND,
	token.EQUALITY:        EQUALS,
	token.INEQUALITY:      EQUALS,
	token.LT:              LESSGREATER,
	token.GT:              LESSGREATER,
	token.LTE:             LESSGREATER,
	token.GTE:             LESSGREATER,
	token.PLUS:            SUM,
	token.MINUS:           SUM,
	token.FSLASH:          PRODUCT,
	token.ASTERISK:        PRODUCT,
	token.MODULO:          PRODUCT,
	// Bitwise precedence is Go's exactly: `<< >> &` sit with `* / %`, and
	// `| ^` sit with `+ -`. That is what makes `flags & MASK == 0` read as
	// `(flags & MASK) == 0` -- C puts bitwise below comparison, and the
	// resulting `flags & (MASK == 0)` is the single most-parenthesised
	// footgun in that family of languages.
	token.SHL:       PRODUCT,
	token.SHR:       PRODUCT,
	token.AMPERSAND: PRODUCT,
	token.PIPE:      SUM,
	token.CARET:     SUM,
	token.INCREMENT: CALL,
	token.DECREMENT: CALL,
	token.LPAREN:    CALL,
	token.LSQUARE:   INDEX,
	token.DOT:       FIELD,
	token.LBRACE:    CALL,
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

// maxNestingDepth bounds how deeply one construct may be nested inside
// another: parenthesised expressions, prefix operators, array and hash
// literals, calls, indexes, function literals and block bodies all count,
// because each one is a frame on the parser's stack.
//
// Source as it is written nests a handful deep and generated source little
// more, so a program past this limit is one built to make the parse recurse,
// and it is refused rather than followed. The value is three orders of
// magnitude above anything a reader would write and three below the point
// where the Go stack gives out: 100,000 levels parsed in 85 ms at HEAD and
// 1,000,000 ended the process with a fatal stack overflow, which recover()
// cannot catch and which therefore takes the language server with it
// (M26-LEX-003).
//
//mutant:limit depth
const maxNestingDepth = 1000

// maxParseErrors bounds how many errors one parse reports.
//
// The errors are a list that grows once per mistake, and some mistakes are one
// per character: every unclosed '(' in a file of them produced its own error,
// so a 700 KB file of nothing else produced 700,001 of them and about a
// megabyte of strings, all saying the same thing about the same program. The
// first hundred are the ones anybody reads; the hundred-and-first is the parse
// repeating itself.
//
//mutant:limit count
const maxParseErrors = 100

type Parser struct {
	l              *lexer.Lexer
	curToken       token.Token
	peekToken      token.Token
	errors         []string
	typedErrors    []ParseError
	recoverables   []RecoverableError
	nodeRanges     map[ast.Node]ast.Range
	parenthesized  map[ast.Node]bool
	prefixParseFns map[token.TokenType]prefixParseFn
	infixParseFns  map[token.TokenType]infixParseFn

	// blockDepth counts how many `{ ... }` bodies enclose the statement being
	// parsed. Only `import` consults it, to reject a nested import: modules
	// are linked into one program before it runs, so an import inside a
	// function body could not mean "load this when control reaches here".
	blockDepth int

	// depth counts the frames of parser recursion currently open, across both
	// expressions and block bodies, and is what maxNestingDepth bounds. It is
	// a different question from blockDepth, which counts only braces and only
	// so that `import` can refuse to be inside one.
	depth int

	// depthReported stops the nesting refusal being appended once per frame as
	// a thousand of them unwind.
	depthReported bool
}

func New(l *lexer.Lexer) *Parser {
	p := &Parser{l: l, errors: []string{}}

	p.prefixParseFns = make(map[token.TokenType]prefixParseFn)
	p.registerPrefix(token.IDENT, p.parseIdentifier)
	p.registerPrefix(token.INT, p.parseIntegerLiteral)
	p.registerPrefix(token.FLOAT, p.parseFloatLiteral)
	p.registerPrefix(token.BANG, p.parsePrefixExpression)
	p.registerPrefix(token.MINUS, p.parsePrefixExpression)
	p.registerPrefix(token.TILDE, p.parsePrefixExpression)
	p.registerPrefix(token.TRUE, p.parseBoolean)
	p.registerPrefix(token.FALSE, p.parseBoolean)
	p.registerPrefix(token.LPAREN, p.parseGroupedExpression)
	p.registerPrefix(token.IF, p.parseIfExpression)
	p.registerPrefix(token.MATCH, p.parseMatchExpression)
	p.registerPrefix(token.FUNCTION, p.parseFunctionLiteral)
	p.registerPrefix(token.STRING, p.parseStringLiteral)
	p.registerPrefix(token.UNTERMINATED, p.parseUnterminatedString)
	p.registerPrefix(token.TEMPLATE, p.parseTemplateLiteral)
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
	p.registerInfix(token.AMPERSAND, p.parseInfixExpression)
	p.registerInfix(token.PIPE, p.parseInfixExpression)
	p.registerInfix(token.CARET, p.parseInfixExpression)
	p.registerInfix(token.SHL, p.parseInfixExpression)
	p.registerInfix(token.SHR, p.parseInfixExpression)
	p.registerInfix(token.ASSIGN, p.parseAssignExpression)
	p.registerInfix(token.PLUS_ASSIGN, p.parseCompoundAssignExpression)
	p.registerInfix(token.MINUS_ASSIGN, p.parseCompoundAssignExpression)
	p.registerInfix(token.ASTERISK_ASSIGN, p.parseCompoundAssignExpression)
	p.registerInfix(token.SLASH_ASSIGN, p.parseCompoundAssignExpression)
	p.registerInfix(token.MODULO_ASSIGN, p.parseCompoundAssignExpression)
	p.registerInfix(token.AND_ASSIGN, p.parseCompoundAssignExpression)
	p.registerInfix(token.OR_ASSIGN, p.parseCompoundAssignExpression)
	p.registerInfix(token.XOR_ASSIGN, p.parseCompoundAssignExpression)
	p.registerInfix(token.SHL_ASSIGN, p.parseCompoundAssignExpression)
	p.registerInfix(token.SHR_ASSIGN, p.parseCompoundAssignExpression)
	p.registerInfix(token.INCREMENT, p.parsePostfixIncDecExpression)
	p.registerInfix(token.DECREMENT, p.parsePostfixIncDecExpression)
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
	// Likewise the expressions written inside brackets, which only the
	// formatter reads.
	if len(p.parenthesized) > 0 {
		program.Parenthesized = p.parenthesized
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

// markParenthesized notes that the author wrote n inside brackets. The tree
// drops them, since precedence is already in its shape; the formatter needs
// them to print back the brackets that were written, and no others.
func (p *Parser) markParenthesized(n ast.Expression) {
	if n == nil {
		return
	}
	if p.parenthesized == nil {
		p.parenthesized = make(map[ast.Node]bool)
	}
	p.parenthesized[n] = true
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
	// Past the cap the parse is repeating itself, so it says so once and stops.
	// The note is appended to errors only: typedErrors is what the language
	// server renders, and a diagnostic about the number of diagnostics has no
	// range to put itself at.
	if len(p.errors) >= maxParseErrors {
		if len(p.errors) == maxParseErrors {
			p.errors = append(p.errors, fmt.Sprintf(
				"too many parse errors; stopped reporting after %d", maxParseErrors))
		}
		return
	}
	p.errors = append(p.errors, msg)
	p.typedErrors = append(p.typedErrors, ParseError{
		Msg:   msg,
		Range: ast.Range{Start: tok.Start, End: tok.End},
	})
}

// enterNesting opens one level of parser recursion and reports whether the
// parse may go deeper. On a refusal the counter is NOT incremented, so the
// frame that was refused owes no matching leaveNesting.
func (p *Parser) enterNesting() bool {
	if p.depth >= maxNestingDepth {
		if !p.depthReported {
			p.depthReported = true
			p.appendError(p.curToken, fmt.Sprintf(
				"nested more than %d levels deep at line %d, column %d: this is past what the parser will follow, and a program written by hand does not reach it",
				maxNestingDepth, p.curToken.Start.Line, p.curToken.Start.Column))
		}
		return false
	}
	p.depth++
	return true
}

// leaveNesting closes the level enterNesting opened.
func (p *Parser) leaveNesting() { p.depth-- }

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

// Precedence is how tightly an infix operator's token binds, or LOWEST for a
// token that is not one. It is the parser's own table, so a printer deciding
// where brackets are needed cannot disagree with how the source parses.
func Precedence(t token.TokenType) int {
	if prec, ok := precedences[t]; ok {
		return prec
	}
	return LOWEST
}

func (p *Parser) peekPrecedence() int {
	return Precedence(p.peekToken.Type)
}

func (p *Parser) curPrecedence() int {
	return Precedence(p.curToken.Type)
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
