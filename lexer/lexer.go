package lexer

import (
	"mutant/token"
	"unicode"
)

// Lexer is the data structure for our lexer
// It performs lexical analysis and tokenizes code.
//
// Position tracking (line, column, offset) is maintained alongside the
// existing cursor state and stamped onto every emitted token so that
// downstream tools (the language server, formatter, linter) can map any
// token back to a source range.
type Lexer struct {
	input        string
	position     int // current character index (byte offset of l.ch)
	readPosition int // next character index (byte offset of the next rune to read)
	ch           rune

	// line is the 1-based line number of l.ch.
	line int
	// lineStart is the byte offset in input at which the current line begins.
	// Column of l.ch = l.position - l.lineStart + 1.
	lineStart int
}

// New function initializes our lexer, takes input as a string
// that input is the source code
func New(input string) *Lexer {
	l := &Lexer{input: input, line: 1, lineStart: 0}
	l.readRune()
	return l
}

// NextToken method makes use of lexer data structure
// Uses switch cases to identify whether a certain character
// in source code is legal or not. Zetsu language only
// supports ascii characters
func (l *Lexer) NextToken() token.Token {
	var tok token.Token

	l.skipTrivia()

	start := l.currentPos()

	switch l.ch {
	case '=':
		if l.peekRune() == '=' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.EQUALITY, Literal: ch + string(l.ch)}
		} else {
			tok = newToken(token.ASSIGN, l.ch)
		}
	case '+':
		tok = newToken(token.PLUS, l.ch)
	case '-':
		tok = newToken(token.MINUS, l.ch)
	case '*':
		tok = newToken(token.ASTERISK, l.ch)
	case '/':
		tok = newToken(token.FSLASH, l.ch)
	case '\\':
		tok = newToken(token.FSLASH, l.ch)
	case '%':
		tok = newToken(token.MODULO, l.ch)
	case '<':
		tok = newToken(token.LT, l.ch)
	case '>':
		tok = newToken(token.GT, l.ch)
	case '!':
		if l.peekRune() == '=' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.INEQUALITY, Literal: ch + string(l.ch)}
		} else {
			tok = newToken(token.BANG, l.ch)
		}
	case '(':
		tok = newToken(token.LPAREN, l.ch)
	case ')':
		tok = newToken(token.RPAREN, l.ch)
	case '{':
		tok = newToken(token.LBRACE, l.ch)
	case '}':
		tok = newToken(token.RBRACE, l.ch)
	case '[':
		tok = newToken(token.LSQUARE, l.ch)
	case ']':
		tok = newToken(token.RSQUARE, l.ch)
	case ',':
		tok = newToken(token.COMMA, l.ch)
	case ':':
		tok = newToken(token.COLON, l.ch)
	case '.':
		tok = newToken(token.DOT, l.ch)
	case ';':
		tok = newToken(token.SEMICOLON, l.ch)
	case 0:
		tok = newToken(token.EOF, l.ch)
		// EOF is a zero-width marker at the current position. Do not
		// advance beyond the end of input. Preserve the legacy Literal
		// value (produced by newToken from l.ch == 0) for back-compat
		// with existing lexer tests that assert on it.
		tok.Start = start
		tok.End = start
		return tok
	case '"':
		tok.Type = token.STRING
		tok.Literal = l.readString()
	default:
		if unicode.IsLetter(l.ch) {
			tok.Literal = l.readIdentifier()
			tok.Type = token.LookupIdent(tok.Literal)
			tok.Start = start
			tok.End = l.currentPos()
			return tok
		} else if unicode.IsNumber(l.ch) {
			val, isFloat := l.readNumber()
			tok.Literal = val
			if isFloat {
				tok.Type = token.FLOAT
			} else {
				tok.Type = token.INT
			}
			tok.Start = start
			tok.End = l.currentPos()
			return tok
		}
		tok = newToken(token.ILLEGAL, l.ch)
	}

	l.readRune()

	tok.Start = start
	tok.End = l.currentPos()
	return tok
}

// currentPos returns the position of the lexer's current cursor (l.ch).
// Line and Column are 1-based; Offset is the 0-based byte offset of l.ch
// within the source input. When the cursor sits past end-of-input, Offset
// equals len(input) and Column points one past the final column of that
// line, giving a valid exclusive-end position for the last token.
func (l *Lexer) currentPos() token.Position {
	return token.Position{
		Line:   l.line,
		Column: l.position - l.lineStart + 1,
		Offset: l.position,
	}
}

func (l *Lexer) prevRune() rune {
	var prev rune
	if l.readPosition >= len(l.input) {
		prev = 0
	} else {
		prev = rune(l.input[l.readPosition-2])
	}
	return prev
}
func (l *Lexer) readRune() {
	// If the currently-active character is a newline, this call moves the
	// cursor onto the first character of the next line, so the line/column
	// counters advance now (before we load the new rune). '\r\n' is handled
	// implicitly: the bump happens when the cursor steps off the '\n'.
	// A lone '\r' is treated as whitespace by skipWhiteSpace without a bump.
	if l.ch == '\n' {
		l.line++
		l.lineStart = l.readPosition
	}

	if l.readPosition >= len(l.input) {
		l.ch = 0
	} else {
		l.ch = rune(l.input[l.readPosition])
	}

	l.position = l.readPosition
	l.readPosition++
}
func (l *Lexer) nextRune() rune {
	var next rune
	if l.readPosition >= len(l.input) {
		next = 0
	} else {
		next = rune(l.input[l.readPosition])
	}
	return next
}

func (l *Lexer) readString() string {
	position := l.position + 1
	for {
		l.readRune()
		if l.ch == '"' || l.ch == 0 {
			break
		}
	}
	return l.input[position:l.position]
}

func newToken(tokenType token.TokenType, ch rune) token.Token {
	var tok token.Token

	tok.Type = tokenType
	tok.Literal = string(ch)

	return tok
}

func (l *Lexer) readIdentifier() string {
	position := l.position
	for unicode.IsLetter(l.ch) || unicode.IsDigit(l.ch) || l.ch == '_' {
		l.readRune()
	}
	return l.input[position:l.position]
}

func (l *Lexer) readNumber() (string, bool) {
	position := l.position
	flag := false
	for unicode.IsDigit(l.ch) || l.ch == '.' {
		if l.ch == '.' {
			flag = true
			prev := l.prevRune()
			next := l.nextRune()
			if !(unicode.IsDigit(prev) && unicode.IsDigit(next)) {
				break
			}
		}

		l.readRune()
	}
	return l.input[position:l.position], flag
}

func (l *Lexer) skipWhiteSpace() {
	for unicode.IsSpace(l.ch) {
		l.readRune()
	}
}

func (l *Lexer) skipTrivia() {
	for {
		l.skipWhiteSpace()
		if l.ch == '/' && l.peekRune() == '/' {
			l.skipLineComment()
			continue
		}
		return
	}
}

func (l *Lexer) skipLineComment() {
	for l.ch != '\n' && l.ch != 0 {
		l.readRune()
	}
}

func (l *Lexer) peekRune() rune {
	if l.readPosition >= len(l.input) {
		return 0
	}
	return rune(l.input[l.readPosition])
}
