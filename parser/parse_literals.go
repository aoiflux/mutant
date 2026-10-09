package parser

import (
	"fmt"
	"math"
	"mutant/ast"
	"mutant/token"
	"strconv"
	"strings"
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

// parseIntegerLiteral reads an integer literal in base ten, and refuses one
// written with a leading zero.
//
// The base is given explicitly because base 0 -- what this used to pass -- read
// a leading zero as octal, so `010` was 8 and `0100 + 1` was 65 with nothing
// said about either (M26-LEX-008). Nothing else base 0 understands can reach
// this function: the literal arrives from the lexer's readNumber, which loops
// on IsDigit and '.', so the text is digits and nothing else. A prefix is split
// off as a separate identifier -- `0x1F` lexes as INT(0) IDENT(x1F), `1_000` as
// INT(1) IDENT(_000) -- so base 0 was never handed one. The leading zero was
// the whole of what it did here.
//
// A float was never read that way -- ParseFloat has no octal -- so `010` was 8
// while `010.5` was 10.5, and the same spelling meant two different things
// depending on whether a '.' followed it. Floats are left alone deliberately:
// no language reads `010.5` as octal, so there is no second reading to refuse.
func (p *Parser) parseIntegerLiteral() ast.Expression {
	// defer untrace(trace("parseIntegerLiteral"))

	start := p.startMark()
	lit := &ast.IntegerLiteral{Token: p.curToken}

	// Refused rather than quietly read as decimal, because both readings are
	// plausible and the text does not say which was meant: a zero-padded field
	// pasted out of a date, a sector listing or tool output means ten, and
	// `0755` written by hand means a permission mask. Reading it either way in
	// silence is wrong for whoever meant the other, and which of the two it is
	// cannot be recovered from the program. This is an error a compile can
	// catch, so it is caught here.
	text := p.curToken.Literal
	if len(text) > 1 && text[0] == '0' {
		decimal := strings.TrimLeft(text, "0")
		if decimal == "" {
			decimal = "0"
		}
		p.appendError(p.curToken, fmt.Sprintf(
			`a leading zero does not make %s octal, and this language has no octal literal: write %s for the decimal value, or parse_int("%s", 8) for the octal one`,
			text, decimal, text))
		return nil
	}

	value, err := strconv.ParseInt(text, 10, 64)

	if err != nil {
		msg := fmt.Sprintf("could not parse %q as integer", text)
		p.appendError(p.curToken, msg)
		return nil
	}

	lit.Value = value

	p.recordRange(lit, start)
	return lit
}

// parseUnterminatedString reports a string literal whose closing delimiter is
// missing, and produces no node.
//
// The position named is where the literal opens -- the `r` of a raw one, not
// its quote, because that is where the token starts -- and it is named because
// it is the only position that helps: the token ends at end of file, and the
// text in between is whatever the scan swallowed, which is the part the author
// cannot see is inside a string.
// There is deliberately no recovery -- no node, and the error is not
// recoverable in the parser's sense -- because every spelling of this was
// accepted in silence and ran a prefix of the program as though it had
// finished (M26-LEX-005).
func (p *Parser) parseUnterminatedString() ast.Expression {
	opening := p.curToken.Start
	p.appendError(p.curToken, fmt.Sprintf(
		"unterminated string literal: the literal opened at line %d, column %d is never closed, so everything after it was read as text",
		opening.Line, opening.Column))
	return nil
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

	// Keys the literal already states, so that one written twice is refused
	// here rather than silently dropping a value at run time.
	seen := make(map[string]bool, 4)

	for !p.peekTokenIs(token.RBRACE) && !p.peekTokenIs(token.EOF) {
		p.nextToken()
		keyToken := p.curToken
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
			// A key written twice is refused where it is written. One of the two
			// values is dropped and the syntax does not say which, which is the
			// same mistake `struct P { a: 1, a: 2 }` is refused for and the same
			// one json_parse gives a document that names a key twice. Refusing it
			// in the parser rather than in the compiler is what makes one refusal
			// serve both engines and the editor, which reads p.TypedErrors().
			//
			// The pair is still appended, so the formatter and every other lint
			// rule see the whole literal rather than a truncated one.
			if tag, spelling, known := constantHashKey(key); known {
				if seen[tag] {
					p.appendError(keyToken, fmt.Sprintf(
						"this hash literal sets the key %s twice: one of the two values would be "+
							"dropped and the syntax does not say which, so set it once",
						spelling))
				}
				seen[tag] = true
			}
			hash.Pairs = append(hash.Pairs, ast.HashPair{Key: key, Value: value})
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

// constantHashKey answers a hash key the parser can already know the value of:
// a tag two keys share exactly when they would be one key at run time, and the
// spelling to name it by in a refusal.
//
// The tag carries the kind as well as the value, because object.HashKey does.
// A hash keeps the integer 1, the float 1.0 and the string "1" apart, so a tag
// of the value alone would refuse three keys that are three keys. The kind is
// also what keeps this honest about ast.StringLiteral.String(), which renders a
// string without its quotes and so renders the literal `"a"` and the identifier
// `a` as one spelling -- the tie that made the compiler fall back to Go map
// iteration (M26-LEX-004).
//
// A float compares by its bits rather than by its value, because
// object.Float.HashKey does: -0.0 and 0.0 are equal numbers and two different
// keys, so comparing them as numbers would refuse a literal that is correct.
//
// Anything whose value is not in the literal answers false and is not compared:
// a name, a call or a sum is a key only the run time knows, and refusing on a
// guess about one would refuse a working program.
func constantHashKey(key ast.Expression) (tag, spelling string, known bool) {
	switch k := key.(type) {
	case *ast.StringLiteral:
		return "string:" + k.Value, strconv.Quote(k.Value), true
	case *ast.IntegerLiteral:
		return "integer:" + strconv.FormatInt(k.Value, 10), strconv.FormatInt(k.Value, 10), true
	case *ast.FloatLiteral:
		return "float:" + strconv.FormatUint(math.Float64bits(k.Value), 16), strconv.FormatFloat(k.Value, 'g', -1, 64), true
	case *ast.Boolean:
		return "boolean:" + strconv.FormatBool(k.Value), strconv.FormatBool(k.Value), true
	}
	return "", "", false
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
