package lexer

import (
	"testing"

	"mutant/token"
)

// M26-LEX-014. token.Position.Column counts BYTES. Nothing in the tree said so
// correctly and nothing measured it: the doc comment on Position claimed runes,
// the language server once passed the column straight through as a UTF-16
// offset (M26-LSP-027), and every test in this package that asserts a Column
// used ASCII, where bytes, runes and UTF-16 units all agree.
//
// The unit is a deliberate choice -- the CLI prints these columns, the parser's
// messages quote them and the sweep goldens pin them, so the conversion an
// editor needs happens once at the protocol boundary instead. A choice nothing
// asserts is not a choice, though: changing the lexer to rune columns would
// pass every other test in this package and then double-convert every position
// the editor is sent. These tests make that fail here, where it is cheap.

// tokenNamed lexes src and returns the first token whose literal is want.
func tokenNamed(t *testing.T, src, want string) token.Token {
	t.Helper()
	l := New(src)
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

func TestAColumnCountsBytesAndNotRunes(t *testing.T) {
	cases := []struct {
		name string
		src  string
		find string
		// Column is 1-based and counts bytes; Offset is the 0-based byte
		// offset of the same place.
		wantColumn int
		wantOffset int
		// What the same token's 1-based column would be if columns counted
		// runes, or UTF-16 code units. Recorded so that each fixture is known
		// to tell the units apart -- a case where all three agree proves
		// nothing, and that is how this went unmeasured for so long.
		runeColumn  int
		utf16Column int
		// allUnitsAgree marks the deliberate ASCII control.
		allUnitsAgree bool
	}{
		{
			name: "ascii only, the control",
			src:  "a b c", find: "b",
			wantColumn: 3, wantOffset: 2, runeColumn: 3, utf16Column: 3,
			allUnitsAgree: true,
		},
		{
			name: "a two-byte character earlier on the line, the row's own repro",
			src:  "a é b", find: "b",
			wantColumn: 6, wantOffset: 5, runeColumn: 5, utf16Column: 5,
		},
		{
			name: "three two-byte characters",
			src:  "ééé b", find: "b",
			wantColumn: 8, wantOffset: 7, runeColumn: 5, utf16Column: 5,
		},
		{
			name: "a four-byte character, where runes and UTF-16 units part company too",
			src:  "\U0001f600 b", find: "b",
			wantColumn: 6, wantOffset: 5, runeColumn: 3, utf16Column: 4,
		},
		{
			name: "non-ascii inside a string literal, which is where it really happens",
			src:  "let s = \"café\"; let b = 2;", find: "b",
			wantColumn: 22, wantOffset: 21, runeColumn: 21, utf16Column: 21,
		},
		{
			name: "an emoji inside a string literal: all three units differ",
			src:  "let s = \"\U0001f600\"; let b = 2;", find: "b",
			wantColumn: 21, wantOffset: 20, runeColumn: 18, utf16Column: 19,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agree := tc.wantColumn == tc.runeColumn && tc.wantColumn == tc.utf16Column
			if agree != tc.allUnitsAgree {
				t.Fatalf("this fixture does not discriminate the way it claims: bytes %d, runes %d, UTF-16 %d",
					tc.wantColumn, tc.runeColumn, tc.utf16Column)
			}
			tok := tokenNamed(t, tc.src, tc.find)
			if tok.Start.Column != tc.wantColumn {
				t.Errorf("Start.Column = %d, want %d (a rune count would say %d, UTF-16 units %d)",
					tok.Start.Column, tc.wantColumn, tc.runeColumn, tc.utf16Column)
			}
			if tok.Start.Offset != tc.wantOffset {
				t.Errorf("Start.Offset = %d, want %d", tok.Start.Offset, tc.wantOffset)
			}
		})
	}
}

func TestAColumnAndAnOffsetMeasureInTheSameUnit(t *testing.T) {
	// The property behind every case above, and the reason a caller can slice
	// the source with either: on the first line of a document Column is
	// Offset+1 whatever the text holds, because both are byte counts from the
	// same cursor. A rune or UTF-16 column breaks this at the first non-ASCII
	// character, so it stands in for the unit without naming a number.
	sources := []string{
		"let b = 2;",
		"let s = \"café\"; let b = 2;",
		"let s = \"\U0001f600\U0001f600\"; let b = 2;",
		"let é = 1; let b = é;",
		"// café \U0001f600\nlet b = 2;",
	}
	for _, src := range sources {
		l := New(src)
		for i := 0; i < 4096; i++ {
			tok := l.NextToken()
			if tok.Type == token.EOF {
				break
			}
			if tok.Start.Line != 1 {
				continue
			}
			if tok.Start.Column != tok.Start.Offset+1 {
				t.Errorf("%q: token %q on line 1 has Column %d and Offset %d; a byte column on one line is the byte offset plus one",
					src, tok.Literal, tok.Start.Column, tok.Start.Offset)
			}
		}
	}
}

func TestEveryLineCountsItsOwnBytesFromTheStartOfThatLine(t *testing.T) {
	// A line after one holding non-ASCII text: the column restarts from the
	// line while the offset does not, which is the other half of what the unit
	// means and the half a per-line conversion would get wrong.
	cases := []struct {
		name   string
		src    string
		before string // everything up to the token, used to state the offset
	}{
		{"after a line holding a two-byte character in a string",
			"let s = \"café\";\nlet b = 2;\nlet é = 3;", "let s = \"café\";\nlet "},
		{"after a comment holding an emoji",
			"// café \U0001f600\nlet b = 2;", "// café \U0001f600\nlet "},
		{"after two non-ascii lines",
			"let é = 1;\nlet \U0001f600 = 2;\nlet b = 3;", "let é = 1;\nlet \U0001f600 = 2;\nlet "},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := tokenNamed(t, tc.src, "b")
			if tok.Start.Column != 5 {
				t.Errorf("Start.Column = %d, want 5: on its own line `b` is the fifth byte of `let b = ...`", tok.Start.Column)
			}
			if want := len(tc.before); tok.Start.Offset != want {
				t.Errorf("Start.Offset = %d, want %d: the offset is into the whole source and does not restart", tok.Start.Offset, want)
			}
		})
	}
}
