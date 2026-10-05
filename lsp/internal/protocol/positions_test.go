package protocol

import (
	"fmt"
	"testing"
	"unicode/utf8"

	mast "mutant/ast"
	"mutant/token"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// quote is a double quote inside a fixture line. Mutant's string literals are
// double-quoted, and several cases here need the quote's own column.
const quote = `"`

// at is a protocol position, written the way a client sends one: a 0-based line
// and a 0-based offset in UTF-16 code units.
func at(line, character int) lsp.Position {
	return lsp.Position{Line: lsp.UInteger(line), Character: lsp.UInteger(character)}
}

// The characters this file measures with, built from their code points so the
// test source stays ASCII and no escape can be mistaken for another.
var (
	// LATIN SMALL LETTER E WITH ACUTE: 2 UTF-8 bytes, 1 UTF-16 unit.
	eAcute = string(rune(0x00E9))
	// EURO SIGN: 3 UTF-8 bytes, 1 UTF-16 unit.
	euro = string(rune(0x20AC))
	// HIRAGANA LETTER A: 3 UTF-8 bytes, 1 UTF-16 unit.
	hira = string(rune(0x3042))
	// GRINNING FACE: 4 UTF-8 bytes, 2 UTF-16 units -- a surrogate pair.
	grin = string(rune(0x1F600))
	// MUSICAL SYMBOL G CLEF: 4 UTF-8 bytes, 2 UTF-16 units.
	clef = string(rune(0x1D11E))
)

func TestTheCharactersThisFileMeasuresWithAreWhatItSaysTheyAre(t *testing.T) {
	for _, c := range []struct {
		name  string
		s     string
		bytes int
		units int
	}{
		{"ASCII", "a", 1, 1},
		{"e-acute", eAcute, 2, 1},
		{"euro", euro, 3, 1},
		{"hiragana", hira, 3, 1},
		{"grinning face", grin, 4, 2},
		{"g clef", clef, 4, 2},
	} {
		if got := len(c.s); got != c.bytes {
			t.Errorf("%s: %d UTF-8 bytes, want %d", c.name, got, c.bytes)
		}
		if got := UTF16Len(c.s); got != c.units {
			t.Errorf("%s: %d UTF-16 units, want %d", c.name, got, c.units)
		}
		if got := utf8.RuneCountInString(c.s); got != 1 {
			t.Errorf("%s: %d runes, want 1", c.name, got)
		}
	}
}

// TestAnASCIILineIsUnchanged is the compatibility guarantee. A byte column and a
// UTF-16 offset are the same number on an ASCII line, so introducing this
// conversion cannot have moved any position in an ASCII document -- which is
// every fixture the rest of this server's tests use.
func TestAnASCIILineIsUnchanged(t *testing.T) {
	src := "let x = 1;\nlet yy = 22;\n"
	m := NewMapper(src)

	for line := 0; line < 2; line++ {
		for byteCol := 0; byteCol <= 14; byteCol++ {
			pos := m.PositionAt(line, byteCol)
			text, _ := m.lineText(line)
			want := byteCol
			if want > len(text) {
				want = len(text) // a column past the end clamps, as it must
			}
			if int(pos.Character) != want {
				t.Errorf("line %d byte %d: character %d, want %d",
					line, byteCol, pos.Character, want)
			}
			if _, col := m.TokenPosition(pos); col != want+1 {
				t.Errorf("line %d byte %d: round trip gave column %d, want %d",
					line, byteCol, col, want+1)
			}
		}
	}
}

// TestByteColumnsBecomeUTF16Offsets is the defect. Each case is a byte column
// the lexer would record and the UTF-16 offset the protocol requires for it;
// equating the two, which is what this server did, is wrong by one unit per
// extra UTF-8 byte from the first non-ASCII character of the line onwards.
func TestByteColumnsBecomeUTF16Offsets(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		byteCol int // 0-based, as the lexer counts
		want    int // 0-based UTF-16 offset
	}{
		{"before any non-ASCII", "let a" + eAcute + " = 1;", 4, 4},
		{"just after a 2-byte rune", "let a" + eAcute + " = 1;", 7, 6},
		{"end of a 2-byte line", "let a" + eAcute + " = 1;", 12, 11},

		{"just after a 3-byte rune", "x = " + quote + euro + quote + ";", 8, 6},
		{"after two 3-byte runes", hira + hira + "ab", 8, 4},

		{"just after a surrogate pair", grin + "ab", 4, 2},
		{"one past that", grin + "ab", 5, 3},
		{"two surrogate pairs", grin + clef + "z", 8, 4},

		{"a comment is enough to trigger it", "let x = 1; // " + euro + " cost", 17, 15},
		{"a string is enough to trigger it", "let s = " + quote + hira + quote + "; x", 15, 13},

		{"column zero", hira + "a", 0, 0},
		{"past the end clamps", hira + "a", 99, 2},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := NewMapper(c.line)
			got := m.PositionAt(0, c.byteCol)
			if int(got.Character) != c.want {
				t.Errorf("byte column %d on %q -> character %d, want %d",
					c.byteCol, c.line, got.Character, c.want)
			}
		})
	}
}

// TestEveryRuneBoundaryRoundTripsBothWays walks each line rune by rune and
// checks that a byte column at a rune boundary converts to a UTF-16 offset and
// back to the same byte column. Both directions, which is the half of this
// defect that a one-way conversion would leave in place.
func TestEveryRuneBoundaryRoundTripsBothWays(t *testing.T) {
	lines := []string{
		"plain ascii only",
		"caf" + eAcute + " au lait",
		hira + hira + hira,
		"price: " + euro + "42",
		grin + " start",
		"end " + clef,
		"mix " + eAcute + " " + euro + " " + grin + " " + clef + " done",
		"",
	}

	for _, line := range lines {
		t.Run(fmt.Sprintf("%d bytes", len(line)), func(t *testing.T) {
			m := NewMapper(line)

			byteCol := 0
			units := 0
			for {
				pos := m.PositionAt(0, byteCol)
				if int(pos.Character) != units {
					t.Fatalf("byte %d -> character %d, want %d", byteCol, pos.Character, units)
				}
				if _, col := m.TokenPosition(pos); col-1 != byteCol {
					t.Fatalf("character %d -> byte %d, want %d", pos.Character, col-1, byteCol)
				}
				if byteCol >= len(line) {
					break
				}
				r, size := utf8.DecodeRuneInString(line[byteCol:])
				byteCol += size
				units++
				if r > 0xFFFF {
					units++
				}
			}

			if units != UTF16Len(line) {
				t.Errorf("walked %d units, UTF16Len says %d", units, UTF16Len(line))
			}
		})
	}
}

// TestAPositionInsideACharacterIsNotAPosition pins the clamping direction. Half
// a rune, or the low half of a surrogate pair, is not a place in the document,
// and clamping down to where the character starts is the only answer that
// cannot name a byte the client never sent.
func TestAPositionInsideACharacterIsNotAPosition(t *testing.T) {
	line := grin + "ab" // bytes 0..3 are one rune, 2 UTF-16 units
	m := NewMapper(line)

	for _, byteCol := range []int{1, 2, 3} {
		if got := m.PositionAt(0, byteCol); got.Character != 0 {
			t.Errorf("byte column %d is inside the first rune; character %d, want 0",
				byteCol, got.Character)
		}
	}

	// UTF-16 offset 1 is the pair's low surrogate.
	if _, col := m.TokenPosition(at(0, 1)); col != 1 {
		t.Errorf("the low surrogate gave byte column %d, want 1 (the rune's start)", col-1+1)
	}
	// Offset 2 is the first real position after it.
	if _, col := m.TokenPosition(at(0, 2)); col != 5 {
		t.Errorf("the character after the pair gave byte column %d, want 5", col)
	}
}

func TestAMultiLineDocumentIndexesEveryLine(t *testing.T) {
	src := "let a = 1;\n" + // line 0, ascii
		"let b = " + quote + euro + quote + ";\n" + // line 1, one 3-byte rune
		grin + " = 2;\n" + // line 2, one surrogate pair
		"" // line 3, the empty line a trailing newline creates
	m := NewMapper(src)

	if got := len(m.lineStart); got != 4 {
		t.Fatalf("indexed %d lines, want 4", got)
	}

	// Line 1: the quote before the euro sign is byte 8, character 8; the quote
	// after it is byte 12, character 10.
	if got := m.PositionAt(1, 8); got.Character != 8 {
		t.Errorf("line 1 byte 8 -> character %d, want 8", got.Character)
	}
	if got := m.PositionAt(1, 12); got.Character != 10 {
		t.Errorf("line 1 byte 12 -> character %d, want 10", got.Character)
	}
	// Line 2: just past the pair is byte 4, character 2.
	if got := m.PositionAt(2, 4); got.Character != 2 {
		t.Errorf("line 2 byte 4 -> character %d, want 2", got.Character)
	}
	// The empty final line has exactly one position.
	if got := m.EndOfLine(3); got.Line != 3 || got.Character != 0 {
		t.Errorf("end of the empty final line is %v, want line 3 character 0", got)
	}
}

func TestACarriageReturnIsAByteTheLexerCounted(t *testing.T) {
	// The lexer counts columns from the start of the line in bytes, so on a CRLF
	// line the '\r' occupies a column. Dropping it here would shift every
	// column on the line by one.
	m := NewMapper("let x = 1;\r\nlet y = 2;\r\n")
	text, ok := m.lineText(0)
	if !ok {
		t.Fatal("line 0 is missing")
	}
	if text != "let x = 1;\r" {
		t.Errorf("line 0 is %q, want it to keep its carriage return", text)
	}
	if got := m.EndOfLine(0); got.Character != 11 {
		t.Errorf("end of line 0 is character %d, want 11", got.Character)
	}
}

func TestEndOfLineCountsUnitsAndNotRunes(t *testing.T) {
	// len([]rune(line)) is what this server used for a document's last position.
	// A surrogate pair is one rune and two units, so a line holding one ended a
	// character short of where the client puts it.
	line := "ab" + grin
	m := NewMapper(line)

	if got := len([]rune(line)); got != 3 {
		t.Fatalf("the fixture has %d runes, want 3", got)
	}
	if got := m.EndOfLine(0); got.Character != 4 {
		t.Errorf("end of line is character %d, want 4 -- the rune count 3 is the defect",
			got.Character)
	}
}

func TestByteOffsetFindsThePlaceInTheDocument(t *testing.T) {
	src := "ab\n" + hira + "cd\n"
	m := NewMapper(src)

	for _, c := range []struct {
		line, character int
		want            int
	}{
		{0, 0, 0},
		{0, 2, 2},
		{1, 0, 3},         // start of line 1
		{1, 1, 3 + 3},     // past the 3-byte rune
		{1, 3, 3 + 5},     // past "cd" too
		{1, 99, 3 + 5},    // clamped to the end of the line
		{2, 0, 3 + 5 + 1}, // the empty final line
	} {
		got, ok := m.ByteOffset(at(c.line, c.character))
		if !ok {
			t.Errorf("line %d character %d: no offset", c.line, c.character)
			continue
		}
		if got != c.want {
			t.Errorf("line %d character %d -> offset %d, want %d",
				c.line, c.character, got, c.want)
		}
		if got > len(src) {
			t.Errorf("line %d character %d -> offset %d, past the %d-byte document",
				c.line, c.character, got, len(src))
		}
	}

	if _, ok := m.ByteOffset(at(99, 0)); ok {
		t.Error("a line the document does not have returned an offset")
	}
}

func TestANilMapperAnswersInByteColumns(t *testing.T) {
	// Documented fallback: a path that never got a mapper is wrong in the way
	// this server was wrong before, rather than panicking inside an editor.
	var m *Mapper
	if got := m.PositionAt(3, 7); got.Line != 3 || got.Character != 7 {
		t.Errorf("nil mapper gave %v, want line 3 character 7", got)
	}
	if _, col := m.TokenPosition(at(3, 7)); col != 8 {
		t.Errorf("nil mapper gave column %d, want 8", col)
	}
	if _, ok := m.ByteOffset(at(0, 0)); ok {
		t.Error("a nil mapper claimed to know a byte offset")
	}
}

func TestAnInvalidTokenPositionStaysInvalid(t *testing.T) {
	m := NewMapper("let x = 1;\n")
	if got := m.Position(token.Position{}); got.Line != 0 || got.Character != 0 {
		t.Errorf("the zero token position became %v, want the zero protocol position", got)
	}
}

func TestContainsPositionConvertsThePositionAndNotTheRange(t *testing.T) {
	// `let caf<e-acute> = 1;` measured byte by byte:
	//
	//   byte  0 1 2 3 4 5 6 7-8 9 10 11 12 13
	//   char  l e t _ c a f  e  _  =  _  1  ;
	//   col   1 2 3 4 5 6 7  8 10 11 12 13 14
	//   unit  0 1 2 3 4 5 6  7  8  9 10 11 12
	//
	// So the identifier is bytes [4,9), 1-based columns [5,10), UTF-16 [4,8].
	line := "let caf" + eAcute + " = 1;"
	m := NewMapper(line)
	rng := mast.Range{
		Start: token.Position{Line: 1, Column: 5, Offset: 4},
		End:   token.Position{Line: 1, Column: 10, Offset: 9},
	}

	for _, character := range []int{4, 5, 6, 7, 8} {
		if !m.ContainsPosition(rng, at(0, character)) {
			t.Errorf("character %d is in the identifier and was not found there", character)
		}
	}
	for _, character := range []int{0, 3, 9, 10} {
		if m.ContainsPosition(rng, at(0, character)) {
			t.Errorf("character %d is outside the identifier and was found inside it", character)
		}
	}

	// The defect, stated exactly. UTF-16 offset 8 is byte 9, column 10 -- the
	// position just past the identifier, which this range counts as inside
	// because its end is inclusive. Equating the offset with a byte column, as
	// this server did, would read offset 8 as column 9: byte 8, the SECOND byte
	// of the e-acute. That is not a column any character starts at.
	if _, col := m.TokenPosition(at(0, 8)); col != 10 {
		t.Errorf("character 8 is byte column %d, want 10", col)
	}
	if _, col := m.TokenPosition(at(0, 9)); col != 11 {
		t.Errorf("character 9 is byte column %d, want 11", col)
	}
	// And nothing converts to column 9, because no character begins there.
	for character := 0; character <= UTF16Len(line); character++ {
		if _, col := m.TokenPosition(at(0, character)); col == 9 {
			t.Errorf("character %d converted to column 9, which is inside a character",
				character)
		}
	}
}

func TestRangeContainsConvertsNothing(t *testing.T) {
	rng := mast.Range{
		Start: token.Position{Line: 2, Column: 5},
		End:   token.Position{Line: 2, Column: 9},
	}
	for _, c := range []struct {
		line, column int
		want         bool
	}{
		{2, 4, false},
		{2, 5, true},
		{2, 8, true},
		{2, 9, true}, // the end is inclusive, as this server has always had it
		{2, 10, false},
		{1, 7, false},
		{3, 7, false},
	} {
		if got := RangeContains(rng, c.line, c.column); got != c.want {
			t.Errorf("line %d column %d: %v, want %v", c.line, c.column, got, c.want)
		}
	}
}
