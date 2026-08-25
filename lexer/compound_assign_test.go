package lexer

import (
	"mutant/token"
	"testing"
)

func TestNextTokenCompoundAssignAndIncDec(t *testing.T) {
	input := `x += 1; x -= 1; x *= 2; x /= 2; x %= 2; x++; x--;`

	tests := []struct {
		expectedType    token.TokenType
		expectedLiteral string
	}{
		{token.IDENT, "x"},
		{token.PLUS_ASSIGN, "+="},
		{token.INT, "1"},
		{token.SEMICOLON, ";"},
		{token.IDENT, "x"},
		{token.MINUS_ASSIGN, "-="},
		{token.INT, "1"},
		{token.SEMICOLON, ";"},
		{token.IDENT, "x"},
		{token.ASTERISK_ASSIGN, "*="},
		{token.INT, "2"},
		{token.SEMICOLON, ";"},
		{token.IDENT, "x"},
		{token.SLASH_ASSIGN, "/="},
		{token.INT, "2"},
		{token.SEMICOLON, ";"},
		{token.IDENT, "x"},
		{token.MODULO_ASSIGN, "%="},
		{token.INT, "2"},
		{token.SEMICOLON, ";"},
		{token.IDENT, "x"},
		{token.INCREMENT, "++"},
		{token.SEMICOLON, ";"},
		{token.IDENT, "x"},
		{token.DECREMENT, "--"},
		{token.SEMICOLON, ";"},
		{token.EOF, "\x00"},
	}

	l := New(input)
	for i, tt := range tests {
		tok := l.NextToken()
		if tok.Type != tt.expectedType {
			t.Fatalf("tests[%d] - tokentype wrong. expected=%q, got=%q (literal %q)", i, tt.expectedType, tok.Type, tok.Literal)
		}
		if tok.Literal != tt.expectedLiteral {
			t.Fatalf("tests[%d] - literal wrong. expected=%q, got=%q", i, tt.expectedLiteral, tok.Literal)
		}
	}
}

// Single-char operators must still lex correctly next to their compound forms
// (maximal munch only kicks in on the actual two-char sequence).
func TestNextTokenSingleCharOperatorsUnaffected(t *testing.T) {
	input := `a + b - c * d / e % f;`
	want := []token.TokenType{
		token.IDENT, token.PLUS, token.IDENT, token.MINUS, token.IDENT,
		token.ASTERISK, token.IDENT, token.FSLASH, token.IDENT, token.MODULO,
		token.IDENT, token.SEMICOLON, token.EOF,
	}
	l := New(input)
	for i, wt := range want {
		tok := l.NextToken()
		if tok.Type != wt {
			t.Fatalf("tests[%d] - expected %q, got %q (%q)", i, wt, tok.Type, tok.Literal)
		}
	}
}
