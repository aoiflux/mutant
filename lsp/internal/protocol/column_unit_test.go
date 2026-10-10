package protocol

import (
	"testing"

	"mutant/lexer"
	"mutant/token"
)

// The two halves of M26-LEX-014 joined up: a real token from the real lexer,
// converted by a real Mapper, measured against the number the protocol asks
// for.
//
// positions_test.go measures the Mapper against byte columns it writes down
// itself. That is the right way to test a conversion, and it cannot catch the
// thing this row is about: the lexer and the Mapper agreeing on what a column
// IS. If the lexer were changed to count runes, every test in that file and
// every test in lexer/ would still pass, and the Mapper would convert an
// already-converted number -- which is M26-LSP-027 again, from the other end.
// This file is the one place both units meet.

func firstTokenNamed(t *testing.T, src, want string) token.Token {
	t.Helper()
	l := lexer.New(src)
	for i := 0; i < 4096; i++ {
		tok := l.NextToken()
		if tok.Type == token.EOF {
			break
		}
		if tok.Literal == want {
			return tok
		}
	}
	t.Fatalf("no token with literal %q in %q", want, src)
	return token.Token{}
}

func TestALexedColumnBecomesTheUnitTheProtocolAsksFor(t *testing.T) {
	cases := []struct {
		name string
		src  string
		find string
		// What the lexer records: a 1-based byte column.
		wantByteColumn int
		// What the client must be sent: a 0-based UTF-16 offset.
		wantCharacter int
	}{
		{
			name: "ascii only, where the conversion has nothing to do",
			src:  "let a = 1; let b = 2;", find: "b",
			wantByteColumn: 16, wantCharacter: 15,
		},
		{
			name: "a two-byte character earlier on the line",
			src:  "let a = \"é\"; let b = 2;", find: "b",
			wantByteColumn: 19, wantCharacter: 17,
		},
		{
			name: "an emoji earlier on the line",
			src:  "let a = \"\U0001f600\"; let b = 2;", find: "b",
			wantByteColumn: 21, wantCharacter: 18,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := firstTokenNamed(t, tc.src, tc.find)
			if tok.Start.Column != tc.wantByteColumn {
				t.Fatalf("the lexer gave Column %d, this test was written against %d: the unit on one side or the other has changed, which is exactly what this file is here to notice",
					tok.Start.Column, tc.wantByteColumn)
			}

			got := NewMapper(tc.src).Position(tok.Start)
			if got.Line != 0 {
				t.Errorf("Line = %d, want 0", got.Line)
			}
			if int(got.Character) != tc.wantCharacter {
				t.Errorf("Character = %d, want %d", got.Character, tc.wantCharacter)
			}

			// And the conversion is doing something: passing the byte column
			// through as the character, which is what this server did before
			// M26-LSP-027 was fixed, gives a different and wrong number on
			// every line that is not pure ASCII.
			passedThrough := tok.Start.Column - 1
			if tc.wantCharacter == passedThrough && tc.name != "ascii only, where the conversion has nothing to do" {
				t.Errorf("the byte column passed through unconverted is %d, the same as the right answer: this fixture cannot tell the fix from the defect", passedThrough)
			}
		})
	}
}

func TestATokenPositionSurvivesTheRoundTrip(t *testing.T) {
	// Both directions, over text where the three units disagree. The Mapper is
	// what the server converts with in each direction, so a token position that
	// does not come back is a position some feature reports in the wrong place.
	sources := []string{
		"let a = 1; let b = 2;",
		"let a = \"é\"; let b = 2;",
		"let a = \"\U0001f600\U0001f600\"; let b = 2;",
		"let é = 1;\nlet b = é;\n",
	}
	for _, src := range sources {
		m := NewMapper(src)
		l := lexer.New(src)
		for i := 0; i < 4096; i++ {
			tok := l.NextToken()
			if tok.Type == token.EOF {
				break
			}
			line, column := m.TokenPosition(m.Position(tok.Start))
			if line != tok.Start.Line || column != tok.Start.Column {
				t.Errorf("%q: token %q at %d:%d came back as %d:%d",
					src, tok.Literal, tok.Start.Line, tok.Start.Column, line, column)
			}
		}
	}
}

func TestTheByteOffsetOfALexedTokenIsWhereItReallyIs(t *testing.T) {
	// ByteOffset is what the analyzer slices the source with -- member
	// completion asks for it on every keystroke. Converting a token's position
	// to the protocol and back to an offset has to land on the token's own
	// Offset, or the text read at the cursor is not the text at the cursor.
	sources := []string{
		"let a = 1; let b = 2;",
		"let a = \"é\"; let b = 2;",
		"let a = \"\U0001f600\"; let b = 2;",
		"let é = 1;\nlet b = é;\n",
	}
	for _, src := range sources {
		m := NewMapper(src)
		l := lexer.New(src)
		for i := 0; i < 4096; i++ {
			tok := l.NextToken()
			if tok.Type == token.EOF {
				break
			}
			offset, ok := m.ByteOffset(m.Position(tok.Start))
			if !ok {
				t.Errorf("%q: no byte offset for token %q", src, tok.Literal)
				continue
			}
			if offset != tok.Start.Offset {
				t.Errorf("%q: token %q is at offset %d, the round trip says %d",
					src, tok.Literal, tok.Start.Offset, offset)
			}
		}
	}
}
