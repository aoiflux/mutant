package lexer

import (
	"strings"
	"testing"
	"unicode/utf8"

	"mutant/token"
)

// tokensUpTo drains the lexer until EOF or until limit tokens have been read,
// whichever comes first, and reports which it was. Every loop in here is
// bounded: the defect under test is a lexer that never reaches EOF, and a test
// that hangs reports nothing.
func tokensUpTo(src string, limit int) (toks []token.Token, reachedEOF bool) {
	l := New(src)
	for i := 0; i < limit; i++ {
		tok := l.NextToken()
		toks = append(toks, tok)
		if tok.Type == token.EOF {
			return toks, true
		}
	}
	return toks, false
}

func TestTheLexerAlwaysReachesEndOfInput(t *testing.T) {
	for _, tt := range []struct{ name, input string }{
		{"a letter with an umlaut", "let grün = 1;"},
		{"an accented letter", "let café = 1;"},
		{"a superscript two", "let x = 2²;"},
		{"a Cyrillic name", "let вода = 1;"},
		{"a lone non-ASCII letter", "ü"},
		{"a vulgar fraction", "¼"},
		{"an emoji", "let x = \"ok\"; // 🙂"},
		{"invalid UTF-8", "let x = 1; \xff\xfe"},
		// The edges of the two predicates. A rune in any of these classes is
		// claimed by one and refused by the other, which is the shape of the
		// stall, so each one is named rather than left to be found again.
		{"a Roman numeral (Nl)", "ⅱ"},
		{"an Arabic-Indic digit (Nd)", "٣"},
		{"a no-break space", "let x = 1;"},
		{"a zero-width space", "let x​ = 1;"},
		{"a line separator", "let x = 1; let y = 2;"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			toks, ok := tokensUpTo(tt.input, 512)
			if !ok {
				t.Fatalf("lexing %q produced 512 tokens without reaching EOF; the last four were %s",
					tt.input, describe(toks[len(toks)-4:]))
			}
		})
	}
}

// TestEveryTokenAdvancesOrIsTheLast pins the property the stall violates: a
// token that is not EOF has to leave the cursor further along than it started,
// or the next call produces the same token again, forever.
func TestEveryTokenAdvancesOrIsTheLast(t *testing.T) {
	for _, input := range []string{"let grün = 1;", "2²", "¼", "в", "x y"} {
		l := New(input)
		for i := 0; i < 512; i++ {
			tok := l.NextToken()
			if tok.Type == token.EOF {
				break
			}
			if tok.End.Offset <= tok.Start.Offset {
				t.Fatalf("lexing %q: token %d is %s %q at offset %d and consumed nothing",
					input, i, tok.Type, tok.Literal, tok.Start.Offset)
			}
		}
	}
}

// TestDistinctNamesAreDistinctIdentifiers is the aliasing half. Both of these
// names begin with a byte the UTF-8 encoding gives to many letters, so a lexer
// that reads bytes sees one name where the author wrote two.
func TestDistinctNamesAreDistinctIdentifiers(t *testing.T) {
	first, _ := tokensUpTo("xà", 8)
	second, _ := tokensUpTo("xÅ", 8)
	if len(first) == 0 || len(second) == 0 {
		t.Fatal("no tokens")
	}
	if first[0].Literal == second[0].Literal {
		t.Fatalf("xa-grave and A-ring both lex to the identifier %q, so one program's name reads as the other's",
			first[0].Literal)
	}
}

// TestAnIdentifierIsValidUTF8 is what makes `mutant fmt` safe to run on a file
// holding a non-ASCII name: the formatter writes a token's literal back out, so
// a literal cut through the middle of a rune becomes invalid UTF-8 on disk.
func TestAnIdentifierIsValidUTF8(t *testing.T) {
	for _, input := range []string{"xà", "grün", "вода", "café"} {
		toks, _ := tokensUpTo(input, 64)
		for _, tok := range toks {
			if tok.Type != token.IDENT {
				continue
			}
			if !utf8.ValidString(tok.Literal) {
				t.Errorf("lexing %q gave the identifier %q, which is not valid UTF-8", input, tok.Literal)
			}
		}
	}
}

// TestANonASCIINameLexesWhole is the positive statement of the fix: the name the
// author wrote is the name the lexer reports, in one token.
func TestANonASCIINameLexesWhole(t *testing.T) {
	for _, tt := range []struct{ input, want string }{
		{"grün", "grün"},
		{"café", "café"},
		{"вода", "вода"},
		{"_ü1", "_ü1"},
	} {
		toks, _ := tokensUpTo(tt.input, 64)
		if len(toks) < 1 || toks[0].Type != token.IDENT || toks[0].Literal != tt.want {
			t.Errorf("lexing %q gave %s, want one IDENT %q", tt.input, describe(toks), tt.want)
		}
	}
}

func describe(toks []token.Token) string {
	var sb strings.Builder
	for i, tok := range toks {
		if i > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(string(tok.Type))
		sb.WriteString("(")
		sb.WriteString(strings.ToValidUTF8(tok.Literal, "?"))
		sb.WriteString(")")
	}
	return sb.String()
}
