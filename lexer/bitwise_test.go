package lexer

import (
	"testing"

	"mutant/token"
)

// The bitwise operators are the only place in the lexer that needs two runes of
// lookahead: `<`, `<<` and `<<=` share a prefix, and so do their `>` mirrors.
// Every one of these cases is a boundary between two tokens that begin the same
// way, which is the only thing that can go wrong here.
func TestBitwiseOperatorTokens(t *testing.T) {
	tests := []struct {
		input string
		want  []token.Token
	}{
		{"&", []token.Token{{Type: token.AMPERSAND, Literal: "&"}}},
		{"&&", []token.Token{{Type: token.AND, Literal: "&&"}}},
		{"&=", []token.Token{{Type: token.AND_ASSIGN, Literal: "&="}}},
		{"|", []token.Token{{Type: token.PIPE, Literal: "|"}}},
		{"||", []token.Token{{Type: token.OR, Literal: "||"}}},
		{"|=", []token.Token{{Type: token.OR_ASSIGN, Literal: "|="}}},
		{"^", []token.Token{{Type: token.CARET, Literal: "^"}}},
		{"^=", []token.Token{{Type: token.XOR_ASSIGN, Literal: "^="}}},
		{"~", []token.Token{{Type: token.TILDE, Literal: "~"}}},
		{"<", []token.Token{{Type: token.LT, Literal: "<"}}},
		{"<=", []token.Token{{Type: token.LTE, Literal: "<="}}},
		{"<<", []token.Token{{Type: token.SHL, Literal: "<<"}}},
		{"<<=", []token.Token{{Type: token.SHL_ASSIGN, Literal: "<<="}}},
		{">", []token.Token{{Type: token.GT, Literal: ">"}}},
		{">=", []token.Token{{Type: token.GTE, Literal: ">="}}},
		{">>", []token.Token{{Type: token.SHR, Literal: ">>"}}},
		{">>=", []token.Token{{Type: token.SHR_ASSIGN, Literal: ">>="}}},

		// Adjacency: `<<` must not be assembled out of two separate `<`
		// comparisons, and `< <` must not collapse into a shift.
		{"a << 2", []token.Token{
			{Type: token.IDENT, Literal: "a"},
			{Type: token.SHL, Literal: "<<"},
			{Type: token.INT, Literal: "2"},
		}},
		{"a < <", []token.Token{
			{Type: token.IDENT, Literal: "a"},
			{Type: token.LT, Literal: "<"},
			{Type: token.LT, Literal: "<"},
		}},
		{"a>>=b", []token.Token{
			{Type: token.IDENT, Literal: "a"},
			{Type: token.SHR_ASSIGN, Literal: ">>="},
			{Type: token.IDENT, Literal: "b"},
		}},
		{"a>>b", []token.Token{
			{Type: token.IDENT, Literal: "a"},
			{Type: token.SHR, Literal: ">>"},
			{Type: token.IDENT, Literal: "b"},
		}},
		{"a>=b", []token.Token{
			{Type: token.IDENT, Literal: "a"},
			{Type: token.GTE, Literal: ">="},
			{Type: token.IDENT, Literal: "b"},
		}},
		// Mutant has no hex literals, so `0xff` is an INT followed by an IDENT.
		// The mask below is therefore two tokens, not one -- pinned here so that
		// adding hex literals later is a deliberate change with a failing test,
		// not a silent one.
		{"~x & 0xff", []token.Token{
			{Type: token.TILDE, Literal: "~"},
			{Type: token.IDENT, Literal: "x"},
			{Type: token.AMPERSAND, Literal: "&"},
			{Type: token.INT, Literal: "0"},
			{Type: token.IDENT, Literal: "xff"},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			l := New(tt.input)
			for i, want := range tt.want {
				got := l.NextToken()
				if got.Type != want.Type || got.Literal != want.Literal {
					t.Fatalf("token %d: got (%s, %q), want (%s, %q)",
						i, got.Type, got.Literal, want.Type, want.Literal)
				}
			}
			if end := l.NextToken(); end.Type != token.EOF {
				t.Fatalf("expected EOF after %d tokens, got (%s, %q)",
					len(tt.want), end.Type, end.Literal)
			}
		})
	}
}

// A lone `&` and a lone `|` used to lex as ILLEGAL, with a comment in the lexer
// saying Mutant had no bitwise operators. Nothing may produce ILLEGAL for them
// any more -- if it does, every mask expression in a program becomes a parse
// error with a message that does not mention the operator.
func TestLoneAmpersandAndPipeAreNoLongerIllegal(t *testing.T) {
	for _, input := range []string{"&", "|", "^", "~"} {
		if tok := New(input).NextToken(); tok.Type == token.ILLEGAL {
			t.Fatalf("%q still lexes as ILLEGAL", input)
		}
	}
}
