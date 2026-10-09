package lexer

import (
	"fmt"
	"strings"

	"mutant/token"
	"unicode"
	"unicode/utf8"
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

	// comments accumulates comment trivia in source order as it is skipped.
	// Comments are never emitted as tokens, so the parser is unaffected;
	// tooling that needs them (the formatter) reads them after lexing via
	// Comments().
	comments []token.Comment
}

// New function initializes our lexer, takes input as a string
// that input is the source code
func New(input string) *Lexer {
	l := &Lexer{input: input, line: 1, lineStart: 0}
	l.readRune()
	return l
}

// NextToken returns the next token of the input. It guarantees that the stream
// it produces ends: every token but EOF consumes at least one rune, so a caller
// draining the lexer reaches EOF.
//
// That guarantee needs stating because it was once untrue, and the cost of it
// being untrue was the whole compiler. The switch below dispatches on one
// predicate and the readers loop on another; a rune the dispatch claims but no
// reader consumes yields a token of zero width, which the next call produces
// again, and again. Nothing notices, because a lexer is not asked whether it is
// finished -- it is read until EOF, and the parser's recovery loop does exactly
// that. So the two halves are kept apart here: scanToken classifies a rune, and
// this decides whether the classification got anywhere.
func (l *Lexer) NextToken() token.Token {
	tok := l.scanToken()
	if tok.Type == token.EOF || tok.End.Offset > tok.Start.Offset {
		return tok
	}

	// Reaching here is a disagreement between a dispatch arm and its reader, not
	// bad input: every spelling of bad input lands on ILLEGAL, and ILLEGAL
	// advances. Report the rune and step over it, so a mistake of that kind
	// costs one wrong token instead of the process.
	tok.Type = token.ILLEGAL
	tok.Literal = string(l.ch)
	l.readRune()
	tok.End = l.currentPos()
	return tok
}

// scanToken reads one token: identifiers and numbers through the readers below,
// everything else decided by the switch. It is NextToken without the promise
// that it moved.
func (l *Lexer) scanToken() token.Token {
	var tok token.Token

	// Trivia can fault, and until now it could end the file: a NUL byte inside
	// a `//` comment stopped the comment scan, and the lexer read that stop as
	// end of input, so every statement after the comment was dropped without a
	// word. The comment is consumed whole before the fault is reported, so the
	// author gets one error at the byte rather than a statement assembled out
	// of the comment's words.
	if fault := l.skipTrivia(); fault.bad() {
		tok.Type = token.ILLEGAL
		tok.Literal = "\x00"
		tok.Err = fault.message()
		tok.Start = fault.where
		tok.End = fault.after()
		return tok
	}

	start := l.currentPos()

	// End of input is a position, not a character. It used to be the character
	// l.ch == 0, which is also what a NUL byte in the file decodes to, so the
	// two were one thing and a program ended at its first NUL. atEOF is the
	// test now, here and in every scan below, and a real NUL falls through the
	// switch to ILLEGAL like any other character no rule begins with.
	if l.atEOF() {
		// A zero-width marker one past the last rune. Its Literal is the
		// "\x00" newToken makes from l.ch, kept because the existing lexer
		// tests assert on it.
		tok = newToken(token.EOF, l.ch)
		tok.Start = start
		tok.End = start
		return tok
	}

	switch l.ch {
	case '=':
		if l.peekRune() == '=' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.EQUALITY, Literal: ch + string(l.ch)}
		} else if l.peekRune() == '>' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.FATARROW, Literal: ch + string(l.ch)}
		} else {
			tok = newToken(token.ASSIGN, l.ch)
		}
	case '+':
		if l.peekRune() == '=' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.PLUS_ASSIGN, Literal: ch + string(l.ch)}
		} else if l.peekRune() == '+' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.INCREMENT, Literal: ch + string(l.ch)}
		} else {
			tok = newToken(token.PLUS, l.ch)
		}
	case '-':
		if l.peekRune() == '=' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.MINUS_ASSIGN, Literal: ch + string(l.ch)}
		} else if l.peekRune() == '-' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.DECREMENT, Literal: ch + string(l.ch)}
		} else {
			tok = newToken(token.MINUS, l.ch)
		}
	case '*':
		if l.peekRune() == '=' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.ASTERISK_ASSIGN, Literal: ch + string(l.ch)}
		} else {
			tok = newToken(token.ASTERISK, l.ch)
		}
	case '/':
		if l.peekRune() == '=' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.SLASH_ASSIGN, Literal: ch + string(l.ch)}
		} else {
			tok = newToken(token.FSLASH, l.ch)
		}
	case '\\':
		tok = newToken(token.FSLASH, l.ch)
	case '%':
		if l.peekRune() == '=' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.MODULO_ASSIGN, Literal: ch + string(l.ch)}
		} else {
			tok = newToken(token.MODULO, l.ch)
		}
	case '<':
		if l.peekRune() == '<' {
			// Two runes of lookahead: the second `<` is consumed before the `=`
			// can be seen, so `<<=` is decided here rather than by a case below.
			ch := string(l.ch)
			l.readRune()
			if l.peekRune() == '=' {
				ch += string(l.ch)
				l.readRune()
				tok = token.Token{Type: token.SHL_ASSIGN, Literal: ch + string(l.ch)}
			} else {
				tok = token.Token{Type: token.SHL, Literal: ch + string(l.ch)}
			}
		} else if l.peekRune() == '=' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.LTE, Literal: ch + string(l.ch)}
		} else {
			tok = newToken(token.LT, l.ch)
		}
	case '>':
		if l.peekRune() == '>' {
			// Two runes of lookahead: the second `>` is consumed before the `=`
			// can be seen, so `>>=` is decided here rather than by a case below.
			ch := string(l.ch)
			l.readRune()
			if l.peekRune() == '=' {
				ch += string(l.ch)
				l.readRune()
				tok = token.Token{Type: token.SHR_ASSIGN, Literal: ch + string(l.ch)}
			} else {
				tok = token.Token{Type: token.SHR, Literal: ch + string(l.ch)}
			}
		} else if l.peekRune() == '=' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.GTE, Literal: ch + string(l.ch)}
		} else {
			tok = newToken(token.GT, l.ch)
		}
	case '!':
		if l.peekRune() == '=' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.INEQUALITY, Literal: ch + string(l.ch)}
		} else {
			tok = newToken(token.BANG, l.ch)
		}
	case '&':
		if l.peekRune() == '&' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.AND, Literal: ch + string(l.ch)}
		} else if l.peekRune() == '=' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.AND_ASSIGN, Literal: ch + string(l.ch)}
		} else {
			tok = newToken(token.AMPERSAND, l.ch)
		}
	case '|':
		if l.peekRune() == '|' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.OR, Literal: ch + string(l.ch)}
		} else if l.peekRune() == '=' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.OR_ASSIGN, Literal: ch + string(l.ch)}
		} else {
			tok = newToken(token.PIPE, l.ch)
		}
	case '^':
		if l.peekRune() == '=' {
			ch := string(l.ch)
			l.readRune()
			tok = token.Token{Type: token.XOR_ASSIGN, Literal: ch + string(l.ch)}
		} else {
			tok = newToken(token.CARET, l.ch)
		}
	case '~':
		// Unary only, so there is no `~=` to look for: `~x = y` would assign to
		// a complement, which is not an lvalue in any language that has one.
		tok = newToken(token.TILDE, l.ch)
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
	case '"':
		tok = l.readStringToken(start.Offset, false, l.peekRune() == '"' && l.peekRuneAt(2) == '"')
	default:
		// End of input was decided before the switch, so a 0 here is a NUL
		// byte in the file. It is ILLEGAL like any other character no rule
		// begins with, and it says so rather than ending the program.
		if l.ch == 0 {
			tok = newToken(token.ILLEGAL, l.ch)
			tok.Err = scanFault{why: faultNUL, where: start}.message()
			break
		}
		// A raw string is spelled r"..." -- the one place an identifier
		// character does not start an identifier. The test is the immediately
		// following quote, which no identifier can be followed by today: there
		// is no infix rule joining a name to a string, so `r"x"` cannot
		// already mean something else.
		if l.ch == 'r' && l.peekRune() == '"' {
			l.readRune() // step onto the opening quote
			tok = l.readStringToken(start.Offset, true, l.peekRune() == '"' && l.peekRuneAt(2) == '"')
			break
		}
		if unicode.IsLetter(l.ch) || l.ch == '_' {
			tok.Literal = l.readIdentifier()
			tok.Type = token.LookupIdent(tok.Literal)
			tok.Start = start
			tok.End = l.currentPos()
			return tok
		} else if unicode.IsDigit(l.ch) {
			// IsDigit, matching readNumber's own loop, and not IsNumber. They are
			// not the same set: IsNumber also holds for the characters whose
			// Unicode category is No or Nl -- a superscript two, a vulgar
			// fraction, a Roman numeral -- and readNumber, which loops on
			// IsDigit, consumes none of them. Dispatching on the wider predicate
			// handed those runes to a reader that would not take them, and a
			// reader that takes nothing returns a token of no width. This is the
			// stall: `let x = 2²;` never finished lexing.
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

// atEOF reports whether the cursor has run past the end of the input, and is
// the only honest test for it.
//
// l.ch is 0 there. l.ch is also 0 on a NUL byte in the file, and reading those
// two as one thing is how a NUL came to mean "the file stops here": a NUL
// between two statements dropped the second, a NUL inside a comment dropped
// the whole program, and `mutant fmt` wrote the truncation back over the
// author's file with no diagnostic at all. readRune clamps position to
// len(input), so this becomes true exactly once the cursor steps off the final
// rune.
func (l *Lexer) atEOF() bool {
	return l.position >= len(l.input)
}

// more reports whether there is another byte after the cursor. It is what the
// escape scans need: they asked `l.peekRune() != 0`, which is the same
// confusion one position further on, so a backslash standing before a NUL byte
// would have been told there was nothing after it.
func (l *Lexer) more() bool {
	return l.readPosition < len(l.input)
}

// scanFault is what a scan found that the source cannot survive: a literal
// with no closing delimiter, a ${ with no closing brace, or a NUL byte. The
// zero value means nothing is wrong.
//
// It is a value and not a field on the Lexer because these scans nest -- a
// hole inside a literal inside a hole -- and a field would let an inner scan
// overwrite the position the outer one is about to report.
type scanFault struct {
	why   string
	where token.Position
}

// The two faults, worded as the author reads them. message() appends the
// position, so each of these is the whole of what the lexer has to say.
//
// A literal with no closing delimiter is not among them. That is
// token.UNTERMINATED, a token type of its own with its own parser handler,
// because it is a token many runes wide that was read correctly and that no
// program can contain -- not a character no rule begins with (M26-LEX-005).
// These two are the other shape: one character inside a construct that was
// otherwise read, which is what an ILLEGAL carrying Err is for.
const (
	faultOpenHole = "unterminated ${ inside a string literal: this hole is never closed by a }"
	faultNUL      = "NUL byte in the source, which a Mutant source file cannot hold -- a string literal that needs one writes \\0"
)

func (f scanFault) bad() bool { return f.why != "" }

// or is f, or g when f is the zero fault. A scan keeps the FIRST fault it
// finds, which is the one nearest the top of the file and so the one to show.
func (f scanFault) or(g scanFault) scanFault {
	if f.bad() {
		return f
	}
	return g
}

// message is the fault with the position it is about. A token carries the range
// of the whole construct it belongs to, which is what an editor underlines;
// the line and column here are the one character inside it that is wrong.
func (f scanFault) message() string {
	return fmt.Sprintf("%s (line %d, column %d)", f.why, f.where.Line, f.where.Column)
}

// after is the position immediately past the faulting character, for a token
// standing for that character alone. Only the NUL fault needs it, and a NUL is
// one byte.
func (f scanFault) after() token.Position {
	return token.Position{
		Line:   f.where.Line,
		Column: f.where.Column + 1,
		Offset: f.where.Offset + 1,
	}
}

// prevRune is the rune before the cursor, or 0 at the start of input. Only
// readNumber asks for it, to tell a decimal point from a field selector.
func (l *Lexer) prevRune() rune {
	if l.position <= 0 {
		return 0
	}
	r, _ := utf8.DecodeLastRuneInString(l.input[:l.position])
	return r
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

	// The cursor is a rune, so it is decoded as one. Reading a byte and widening
	// it was the same expression for ASCII and for nothing else: it produced the
	// first byte of a multi-byte letter, and that byte is itself a letter in
	// Latin-1 -- 0xc3 is A-tilde -- so the scan took it as the whole letter,
	// stopped one byte into the name, and left the rest to be lexed as something
	// else. Every letter whose UTF-8 form starts 0xc3 then read as the same
	// identifier, which is how two different names became one variable.
	//
	// Invalid UTF-8 decodes to RuneError with a width of 1. No scan predicate
	// claims RuneError, so bad bytes become one ILLEGAL token each: reported,
	// one position at a time, rather than silently misread.
	width := 1
	if l.readPosition >= len(l.input) {
		// Past the end l.ch is 0 -- and so is a NUL byte in the file. This
		// assignment stays only because the EOF token's Literal is made from
		// it and the existing tests assert on that. Nothing may test l.ch for
		// the end of input; atEOF is the test.
		l.ch = 0
	} else {
		l.ch, width = utf8.DecodeRuneInString(l.input[l.readPosition:])
	}

	// readPosition runs one past the end and keeps going -- a scan that calls
	// readRune again after hitting end of input is ordinary, and each call has
	// to leave the cursor somewhere. position is different: every use of it is
	// an index into input, either to slice a token's text or to record an
	// offset in a Mark. Letting it run past the end turns one of those slices
	// into a panic instead of a parse error, which is what happened to
	// `"${ f(\"a\") }"`: the backslash is not an escape inside a hole, so the
	// quote after it opened a string scan that consumed the rest of the file.
	// That source is wrong either way, but wrong source is reported, not
	// crashed on.
	l.position = min(l.readPosition, len(l.input))
	l.readPosition += width
}

// nextRune is peekRune under the name readNumber reads better with, where it
// stands beside prevRune.
func (l *Lexer) nextRune() rune {
	return l.peekRune()
}

// readQuotedBody returns the source text between the quotes of an ordinary
// string literal, exactly as written -- escapes not yet decoded.
//
// Splitting the scan from the decode is what lets one body be read twice: once
// to find the ${...} holes, which have to be located in the source spelling,
// and once per literal chunk to decode it. It is also the only way to report a
// position inside a string, since a decoded byte has no source offset.
//
// A backslash consumes the character after it so that \" does not end the
// literal. A newline does not end it either, which is long-standing behaviour:
// a lone " spanning lines has always been legal, and triple quotes are for
// saying so on purpose.
//
// The second return says whether the closing quote was found. End of input and
// a closing quote both stop this loop and used to be indistinguishable to the
// caller, which is why an unterminated literal became an ordinary STRING
// holding the rest of the file (M26-LEX-005).
//
// The third carries out what a hole inside the literal found. The stop test is
// atEOF and not `l.ch == 0`, because a NUL byte in the file decodes to the same
// zero: a literal holding one ended here, and the quote that really closed it
// was then read as the opening of the next (M26-LEX-006). The escape test is
// l.more() for the same reason one position further on -- a backslash standing
// before a NUL was told there was nothing after it.
func (l *Lexer) readQuotedBody() (string, bool, scanFault) {
	start := l.readPosition
	var fault scanFault
	for {
		l.readRune()
		if l.atEOF() {
			return l.input[start:l.position], false, fault
		}
		if l.ch == '"' {
			break
		}
		if l.ch == '\\' && l.more() {
			l.readRune()
			continue
		}
		// Inside a hole a quote belongs to the expression, not to the literal:
		// "${ h["k"] }" ends at the last quote, not at the third.
		if l.ch == '$' && l.peekRune() == '{' {
			fault = fault.or(l.skipHole())
		}
	}
	return l.input[start:l.position], true, fault
}

// skipHole advances the cursor from the `$` of a `${` to the matching `}`,
// counting nested braces and stepping over whole string literals on the way,
// and reports whether it found the brace.
//
// The comment here used to read "an unterminated hole runs to end of input,
// where the caller stops anyway", which is true and is the defect: the caller
// stopped because this had eaten the rest of the file. It now names the `${`
// it could not close, and the caller refuses the literal.
func (l *Lexer) skipHole() scanFault {
	open := l.currentPos()
	l.readRune() // onto the brace
	depth := 1
	for depth > 0 {
		l.readRune()
		if l.atEOF() {
			return scanFault{why: faultOpenHole, where: open}
		}
		switch l.ch {
		case '{':
			depth++
		case '}':
			depth--
		case '"':
			for {
				l.readRune()
				if l.atEOF() {
					return scanFault{why: faultOpenHole, where: open}
				}
				if l.ch == '"' {
					break
				}
				if l.ch == '\\' && l.more() {
					l.readRune()
				}
			}
		}
	}
	return scanFault{}
}

// readRawBody reads the text of an r"..." literal. There are no escapes, so
// the literal ends at the first quote and a raw string cannot contain one --
// that is the entire rule, and r"""..."""  is how a program gets a quote back.
// The cursor starts on the opening quote and is left on the closing one.
//
// The second return says whether that closing quote was found. The stop test
// is atEOF, so a NUL byte inside the literal no longer ends it (M26-LEX-006).
func (l *Lexer) readRawBody() (string, bool) {
	start := l.readPosition
	for {
		l.readRune()
		if l.atEOF() {
			return l.input[start:l.position], false
		}
		if l.ch == '"' {
			return l.input[start:l.position], true
		}
	}
}

// readTripleBody returns the source text between the delimiters of a
// """...""" literal. The cursor starts on the first of the three opening
// quotes and is left on the last of the three closing ones.
//
// The second return says whether all three closing quotes were found. This
// scanner already distinguished the two endings internally -- it set end from
// l.position in one arm and stepped over the delimiter in the other -- and
// threw the distinction away at the return.
func (l *Lexer) readTripleBody(raw bool) (string, bool) {
	l.readRune()
	l.readRune()

	start := l.readPosition
	end := len(l.input)
	terminated := false
	for {
		l.readRune()
		if l.atEOF() {
			end = l.position
			break
		}
		if l.ch == '"' && l.peekRune() == '"' && l.peekRuneAt(2) == '"' {
			end = l.position
			l.readRune()
			l.readRune()
			terminated = true
			break
		}
		if !raw && l.ch == '\\' && l.more() {
			l.readRune()
		}
	}

	return l.input[start:end], terminated
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

func (l *Lexer) skipTrivia() scanFault {
	var fault scanFault
	for {
		l.skipWhiteSpace()
		if l.ch == '/' && l.peekRune() == '/' {
			fault = fault.or(l.skipLineComment())
			continue
		}
		return fault
	}
}

// skipLineComment consumes a `// ...` comment up to (but not including) the
// terminating newline, recording it as trivia, and reports a NUL byte inside
// it. The cursor is left on the newline (or EOF) so the enclosing skipTrivia
// loop keeps line accounting intact.
//
// The loop used to stop on l.ch == 0 as well as on a newline, which made a NUL
// byte in a comment the end of the file: `// hi<NUL>` followed by a whole
// program lexed as that one comment and nothing else, and `mutant fmt` then
// wrote the comment back over the file. The comment is consumed whole now and
// the byte is reported afterwards, so it costs one error rather than a cascade
// of identifiers made out of the comment's words.
func (l *Lexer) skipLineComment() scanFault {
	start := l.currentPos()
	for l.ch != '\n' && !l.atEOF() {
		l.readRune()
	}
	end := l.currentPos()

	text := l.input[start.Offset:end.Offset]

	// On CRLF input the '\r' sits before the '\n' and would otherwise be
	// captured as part of the comment body. Drop it from both the text and
	// the recorded end position so they stay consistent.
	if strings.HasSuffix(text, "\r") {
		text = text[:len(text)-1]
		end.Offset--
		end.Column--
	}

	l.comments = append(l.comments, token.Comment{
		Kind:  token.LineComment,
		Text:  text,
		Start: start,
		End:   end,
	})

	if at := strings.IndexByte(text, 0); at >= 0 {
		return scanFault{why: faultNUL, where: advance(start, text[:at])}
	}
	return scanFault{}
}

// Comments returns the comment trivia lexed so far, in source order.
//
// Because lexing is lazy, the result is only complete once the input has
// been consumed through EOF. Callers that need every comment (the parser,
// which publishes them on ast.Program) should read this after parsing
// finishes rather than mid-stream. The returned slice aliases the lexer's
// storage and must not be mutated.
func (l *Lexer) Comments() []token.Comment {
	if l == nil {
		return nil
	}
	return l.comments
}

func (l *Lexer) peekRune() rune {
	if l.readPosition >= len(l.input) {
		return 0
	}
	r, _ := utf8.DecodeRuneInString(l.input[l.readPosition:])
	return r
}

// peekRuneAt looks n runes ahead of the cursor; peekRuneAt(1) is peekRune. Only
// the string readers need to look further than one, to tell """ from an empty
// string followed by something else.
//
// Runes, not bytes: the delimiters it is asked about are ASCII, but what sits
// between the cursor and them need not be, and stepping a fixed number of bytes
// would land inside a letter and compare its tail against a quote.
func (l *Lexer) peekRuneAt(n int) rune {
	if n < 1 {
		return 0
	}
	idx := l.readPosition
	for i := 1; i < n; i++ {
		if idx >= len(l.input) {
			return 0
		}
		_, width := utf8.DecodeRuneInString(l.input[idx:])
		idx += width
	}
	if idx >= len(l.input) {
		return 0
	}
	r, _ := utf8.DecodeRuneInString(l.input[idx:])
	return r
}

// unescape decodes the backslash sequences an ordinary string literal
// understands: \n \r \t \" \\ \0 and \$. Anything else is kept verbatim, both
// characters, which is what makes a Windows path in an ordinary string merely
// tedious rather than wrong. A trailing backslash stays a backslash.
//
// \$ is the escape hatch for interpolation: a lone $ is still a $, so only the
// two characters ${ ever need one.
func unescape(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}

	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			sb.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) {
			sb.WriteByte('\\')
			break
		}
		i++
		switch s[i] {
		case 'n':
			sb.WriteByte('\n')
		case 'r':
			sb.WriteByte('\r')
		case 't':
			sb.WriteByte('\t')
		case '"':
			sb.WriteByte('"')
		case '\\':
			sb.WriteByte('\\')
		case '$':
			sb.WriteByte('$')
		case '0':
			sb.WriteByte(0)
		default:
			sb.WriteByte('\\')
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
}

// normalizeNewlines turns CRLF into LF inside a multi-line literal.
//
// The newlines in a triple-quoted string come from the file's line endings,
// and those are a property of the checkout rather than of the program. Without
// this the same source would produce a different string depending on how it
// was cloned. A program that wants a carriage return writes \r.
func normalizeNewlines(s string) string {
	if !strings.Contains(s, "\r\n") {
		return s
	}
	return strings.ReplaceAll(s, "\r\n", "\n")
}

// stripBlockIndent removes the indentation a triple-quoted literal inherits
// from the code it is written inside.
//
// Stripping happens only when the opening """ is alone on its line: that is
// the form that has indentation to inherit, and a literal that starts text on
// the opening line is one whose first line has no indentation to measure. The
// amount removed is the smallest indentation of any non-blank line, counting
// the line the closing """ sits on when it is alone on one -- so aligning the
// closer with the text, which is what anybody does by reflex, is also what
// says where the left margin is.
//
// Indentation is counted in characters, so a tab is one. Mixing tabs and
// spaces in the same block therefore strips a consistent number of characters
// rather than a consistent visual width.
func stripBlockIndent(body string) string {
	newline := strings.IndexByte(body, '\n')
	if newline < 0 || strings.TrimLeft(body[:newline], " \t") != "" {
		return body
	}
	body = body[newline+1:]

	lines := strings.Split(body, "\n")
	indent := -1
	if last := lines[len(lines)-1]; strings.TrimLeft(last, " \t") == "" {
		indent = len(last)
		lines = lines[:len(lines)-1]
	}

	for _, line := range lines {
		if strings.TrimLeft(line, " \t") == "" {
			continue
		}
		if width := len(line) - len(strings.TrimLeft(line, " \t")); indent < 0 || width < indent {
			indent = width
		}
	}

	if indent > 0 {
		for i, line := range lines {
			if len(line) < indent {
				lines[i] = strings.TrimLeft(line, " \t")
				continue
			}
			lines[i] = line[indent:]
		}
	}
	return strings.Join(lines, "\n")
}

// readStringToken reads a complete string literal in any of its spellings and
// returns the token for it, already classified: a literal holding at least one
// ${...} hole becomes a TEMPLATE carrying its parts, everything else stays a
// STRING carrying its decoded text.
//
// openOffset is the offset of the literal's first character -- the `r` of a
// raw one, not its quote -- so the spelling recorded on the token is the whole
// thing. The cursor starts on the first quote and is left on the last one,
// which is the contract NextToken's trailing readRune() expects.
func (l *Lexer) readStringToken(openOffset int, raw, triple bool) token.Token {
	bodyStart := l.bodyPosition(triple)

	var body string
	var terminated bool
	var fault scanFault
	switch {
	case triple:
		body, terminated = l.readTripleBody(raw)
	case raw:
		body, terminated = l.readRawBody()
	default:
		body, terminated, fault = l.readQuotedBody()
	}

	end := l.readPosition
	if end > len(l.input) {
		end = len(l.input)
	}
	spelling := l.input[openOffset:end]

	// A raw NUL in the body cannot be carried any further. stripBlockIndent
	// joins a triple-quoted literal's lines with one as its marker, on the
	// stated invariant that a literal cannot already hold one -- and nothing
	// checked it, so a NUL in the source made the marker ambiguous and the
	// block was re-indented along a line the author never wrote. Now that the
	// scans above read past a NUL instead of stopping at it, a literal can
	// reach here holding one, so this is the check that invariant always
	// needed (M26-LEX-006).
	if at := strings.IndexByte(body, 0); at >= 0 {
		fault = fault.or(scanFault{why: faultNUL, where: advance(bodyStart, body[:at])})
	}

	// Reported ahead of the unterminated literal that usually comes with it,
	// because a hole left open consumes the rest of the literal and the
	// unclosed quote is the consequence rather than the mistake: the `${` is
	// the position the author has to be sent to. The token stands for the whole
	// literal, which is what an editor underlines; the line and column in the
	// message are the one character inside it that is wrong.
	if fault.bad() {
		return token.Token{Type: token.ILLEGAL, Literal: spelling, Raw: spelling, Err: fault.message()}
	}

	// Returned before the template check on purpose: a literal that was never
	// closed has no parts to split, and splitting it would report a hole's
	// position inside text the program does not contain. The decoded body is
	// carried so a caller that wants to show what was swallowed can, and the
	// caller that matters -- the parser -- shows where the quote was opened.
	if !terminated {
		return token.Token{Type: token.UNTERMINATED, Literal: body, Raw: spelling}
	}

	// A raw literal has no holes for the same reason it has no escapes: raw
	// means the text is the text. Nothing else would make r"${x}" usable for
	// the shell and template snippets it exists to hold.
	if !raw {
		parts, interpolated, holeFault := splitTemplate(body, bodyStart)
		// This is the hole fault the quoted path cannot raise, and the reason
		// the row is not closed by the quoted path alone: a """...""" literal
		// closes on its own delimiter, so `"""v=${1+2"""` is a literal that
		// ends properly around a hole that never does. It read as a finished
		// template and evaluated to v=3 -- an expression the author never
		// wrote the end of (M26-LEX-017).
		if holeFault.bad() {
			return token.Token{Type: token.ILLEGAL, Literal: spelling, Raw: spelling, Err: holeFault.message()}
		}
		if interpolated {
			return token.Token{
				Type:    token.TEMPLATE,
				Literal: body,
				Raw:     spelling,
				Parts:   decodeParts(parts, triple),
			}
		}
	}

	decoded := body
	if triple {
		decoded = stripBlockIndent(normalizeNewlines(decoded))
	}
	if !raw {
		decoded = unescape(decoded)
	}

	tok := token.Token{Type: token.STRING, Literal: decoded}
	if raw || triple {
		// An ordinary literal is left without a spelling on purpose: the
		// formatter re-quotes its decoded value, which canonicalises escapes.
		// These two spellings say something the decoded value cannot.
		tok.Raw = spelling
	}
	return tok
}

// bodyPosition returns the position of the first character inside the literal
// whose opening quote the cursor is currently on.
func (l *Lexer) bodyPosition(triple bool) token.Position {
	skip := 1
	if triple {
		skip = 3
	}
	return token.Position{
		Line:   l.line,
		Column: l.position - l.lineStart + 1 + skip,
		Offset: l.position + skip,
	}
}

// splitTemplate cuts a literal's source body into alternating text and ${...}
// hole parts, starting at start, and reports whether it found a hole at all and
// whether any hole was left open.
//
// Text parts are returned still encoded, because what a triple-quoted literal
// does to its indentation has to be decided across the whole block and so
// cannot happen here; decodeParts finishes them. Text parts are also emitted
// even when empty, so that the parts alternate strictly -- decodeParts relies
// on that to line the block up again, and the empty ones are dropped there.
func splitTemplate(body string, start token.Position) ([]token.StringPart, bool, scanFault) {
	if !strings.Contains(body, "${") {
		return nil, false, scanFault{}
	}

	parts := []token.StringPart{}
	pos := start
	textStart := start
	var text strings.Builder
	found := false
	var fault scanFault

	flushText := func(at token.Position) {
		parts = append(parts, token.StringPart{Text: text.String(), Start: textStart})
		text.Reset()
		textStart = at
	}

	for i := 0; i < len(body); {
		// A backslash takes the next character with it, so \${ is two
		// characters of text rather than the start of a hole.
		if body[i] == '\\' && i+1 < len(body) {
			text.WriteString(body[i : i+2])
			pos = advance(pos, body[i:i+2])
			i += 2
			continue
		}

		if body[i] == '$' && i+1 < len(body) && body[i+1] == '{' {
			exprStart := advance(pos, "${")
			source, next, closed := scanHole(body, i)
			if !closed {
				// The `${` is where the author has to go, not the end of the
				// literal, which is only where the scan gave up.
				fault = fault.or(scanFault{why: faultOpenHole, where: pos})
			}
			flushText(exprStart)
			parts = append(parts, token.StringPart{
				Text:       source,
				Expression: true,
				Start:      exprStart,
			})
			pos = advance(pos, body[i:next])
			textStart = pos
			i = next
			found = true
			continue
		}

		text.WriteByte(body[i])
		pos = advance(pos, body[i:i+1])
		i++
	}
	flushText(pos)

	return parts, found, fault
}

// scanHole returns the source between the braces of the hole starting at
// body[i] (which is the `$` of a `${`), the index just past its `}`, and
// whether it found that `}`.
//
// Braces nest and a string inside the hole is skipped whole, so
// "${ hash[ "${k}" ] }" closes where a reader would say it closes.
//
// This used to promise what it did not deliver. The comment read: "An
// unterminated hole runs to the end of the literal and is handed to the parser
// as it stands: the resulting error points inside the string, which is where
// the missing brace is." There is no such error. A hole with no `}` was closed
// here, at the end of the literal, and `let a = """v=${1+2""";` compiled and
// set a to v=3 -- an expression the author never finished, evaluated as though
// they had. closed is how the caller finds out.
func scanHole(body string, i int) (source string, next int, closed bool) {
	depth := 1
	j := i + 2
	for j < len(body) && depth > 0 {
		switch body[j] {
		case '{':
			depth++
		case '}':
			depth--
		case '"':
			j++
			for j < len(body) && body[j] != '"' {
				if body[j] == '\\' {
					j++
				}
				j++
			}
		}
		j++
	}
	if depth > 0 {
		return body[i+2:], len(body), false
	}
	return body[i+2 : j-1], j, true
}

// decodeParts finishes the text parts splitTemplate left encoded and drops the
// empty ones.
//
// A triple-quoted literal's indentation belongs to the block, not to any one
// part, so the text is reassembled with a NUL standing in for each hole,
// re-indented as a whole, and cut apart again. A NUL is safe as the marker
// because it is one character, so it cannot change a line's indentation, and
// because the only way to get one into a literal is the \0 escape, which is
// still two characters at this point -- an invariant readStringToken now
// enforces by refusing a literal that holds a raw NUL byte, where before
// nothing checked it.
func decodeParts(parts []token.StringPart, triple bool) []token.StringPart {
	if triple {
		var masked strings.Builder
		for _, part := range parts {
			if part.Expression {
				masked.WriteByte(0)
				continue
			}
			masked.WriteString(part.Text)
		}

		chunks := strings.Split(stripBlockIndent(normalizeNewlines(masked.String())), "\x00")
		next := 0
		for i := range parts {
			if parts[i].Expression || next >= len(chunks) {
				continue
			}
			parts[i].Text = chunks[next]
			next++
		}
	}

	decoded := make([]token.StringPart, 0, len(parts))
	for _, part := range parts {
		if !part.Expression {
			part.Text = unescape(part.Text)
			if part.Text == "" {
				continue
			}
		}
		decoded = append(decoded, part)
	}
	return decoded
}

// advance moves a position forward over text, keeping line and column honest
// so that a hole several lines into a triple-quoted literal still reports the
// line it is on.
func advance(pos token.Position, text string) token.Position {
	for i := 0; i < len(text); i++ {
		pos.Offset++
		if text[i] == '\n' {
			pos.Line++
			pos.Column = 1
			continue
		}
		pos.Column++
	}
	return pos
}
