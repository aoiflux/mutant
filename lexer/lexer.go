package lexer

import (
	"strings"

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
		tok = l.readStringToken(start.Offset, false, l.peekRune() == '"' && l.peekRuneAt(2) == '"')
	default:
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
func (l *Lexer) readQuotedBody() string {
	start := l.readPosition
	for {
		l.readRune()
		if l.ch == 0 || l.ch == '"' {
			break
		}
		if l.ch == '\\' && l.peekRune() != 0 {
			l.readRune()
			continue
		}
		// Inside a hole a quote belongs to the expression, not to the literal:
		// "${ h["k"] }" ends at the last quote, not at the third.
		if l.ch == '$' && l.peekRune() == '{' {
			l.skipHole()
		}
	}
	return l.input[start:l.position]
}

// skipHole advances the cursor from the `$` of a `${` to the matching `}`,
// counting nested braces and stepping over whole string literals on the way.
// An unterminated hole runs to end of input, where the caller stops anyway.
func (l *Lexer) skipHole() {
	l.readRune() // onto the brace
	depth := 1
	for depth > 0 {
		l.readRune()
		switch l.ch {
		case 0:
			return
		case '{':
			depth++
		case '}':
			depth--
		case '"':
			for {
				l.readRune()
				if l.ch == 0 || l.ch == '"' {
					break
				}
				if l.ch == '\\' && l.peekRune() != 0 {
					l.readRune()
				}
			}
		}
	}
}

// readRawBody reads the text of an r"..." literal. There are no escapes, so
// the literal ends at the first quote and a raw string cannot contain one --
// that is the entire rule, and r"""..."""  is how a program gets a quote back.
// The cursor starts on the opening quote and is left on the closing one.
func (l *Lexer) readRawBody() string {
	start := l.readPosition
	for {
		l.readRune()
		if l.ch == 0 || l.ch == '"' {
			break
		}
	}
	return l.input[start:l.position]
}

// readTripleBody returns the source text between the delimiters of a
// """...""" literal. The cursor starts on the first of the three opening
// quotes and is left on the last of the three closing ones.
func (l *Lexer) readTripleBody(raw bool) string {
	l.readRune()
	l.readRune()

	start := l.readPosition
	end := len(l.input)
	for {
		l.readRune()
		if l.ch == 0 {
			end = l.position
			break
		}
		if l.ch == '"' && l.peekRune() == '"' && l.peekRuneAt(2) == '"' {
			end = l.position
			l.readRune()
			l.readRune()
			break
		}
		if !raw && l.ch == '\\' && l.peekRune() != 0 {
			l.readRune()
		}
	}

	return l.input[start:end]
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

// skipLineComment consumes a `// ...` comment up to (but not including) the
// terminating newline, recording it as trivia. The cursor is left on the
// newline (or EOF) so the enclosing skipTrivia loop keeps line accounting
// intact.
func (l *Lexer) skipLineComment() {
	start := l.currentPos()
	for l.ch != '\n' && l.ch != 0 {
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
	return rune(l.input[l.readPosition])
}

// peekRuneAt looks n characters ahead of the cursor; peekRuneAt(1) is
// peekRune. Only the string readers need to look further than one, to tell
// """ from an empty string followed by something else.
func (l *Lexer) peekRuneAt(n int) rune {
	idx := l.readPosition + n - 1
	if idx < 0 || idx >= len(l.input) {
		return 0
	}
	return rune(l.input[idx])
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
	switch {
	case triple:
		body = l.readTripleBody(raw)
	case raw:
		body = l.readRawBody()
	default:
		body = l.readQuotedBody()
	}

	end := l.readPosition
	if end > len(l.input) {
		end = len(l.input)
	}
	spelling := l.input[openOffset:end]

	// A raw literal has no holes for the same reason it has no escapes: raw
	// means the text is the text. Nothing else would make r"${x}" usable for
	// the shell and template snippets it exists to hold.
	if !raw {
		if parts, interpolated := splitTemplate(body, bodyStart); interpolated {
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
// hole parts, starting at start, and reports whether it found a hole at all.
//
// Text parts are returned still encoded, because what a triple-quoted literal
// does to its indentation has to be decided across the whole block and so
// cannot happen here; decodeParts finishes them. Text parts are also emitted
// even when empty, so that the parts alternate strictly -- decodeParts relies
// on that to line the block up again, and the empty ones are dropped there.
func splitTemplate(body string, start token.Position) ([]token.StringPart, bool) {
	if !strings.Contains(body, "${") {
		return nil, false
	}

	parts := []token.StringPart{}
	pos := start
	textStart := start
	var text strings.Builder
	found := false

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
			source, next := scanHole(body, i)
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

	return parts, found
}

// scanHole returns the source between the braces of the hole starting at
// body[i] (which is the `$` of a `${`), and the index just past its `}`.
//
// Braces nest and a string inside the hole is skipped whole, so
// "${ hash[ "${k}" ] }" closes where a reader would say it closes. An
// unterminated hole runs to the end of the literal and is handed to the parser
// as it stands: the resulting error points inside the string, which is where
// the missing brace is.
func scanHole(body string, i int) (source string, next int) {
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
		return body[i+2:], len(body)
	}
	return body[i+2 : j-1], j
}

// decodeParts finishes the text parts splitTemplate left encoded and drops the
// empty ones.
//
// A triple-quoted literal's indentation belongs to the block, not to any one
// part, so the text is reassembled with a NUL standing in for each hole,
// re-indented as a whole, and cut apart again. A NUL is safe as the marker
// because it is one character, so it cannot change a line's indentation, and
// because the only way to get one into a literal is the \0 escape, which is
// still two characters at this point.
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
