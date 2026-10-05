package protocol

import (
	"strings"
	"unicode/utf8"

	mast "mutant/ast"
	"mutant/token"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// Mapper translates between the byte columns Mutant records and the UTF-16 code
// unit offsets the protocol requires.
//
// LSP 3.16 defines Position.character as an offset in UTF-16 code units and
// gives no way to negotiate anything else: positionEncoding arrived in 3.17 and
// this server is built on protocol_3_16. Mutant's lexer counts columns in BYTES
// -- currentPos is l.position - l.lineStart + 1 -- and token.Position carries
// that byte column into the AST, the parser's messages and the CLI.
//
// The two numbers agree on an ASCII line and on no other. From the first
// non-ASCII byte of a line onwards they drift apart by one unit per extra UTF-8
// byte, so a range sent out lands too far right and a position read in is taken
// too far left. The trigger is not a non-ASCII identifier: a non-ASCII character
// anywhere earlier on the line does it, a string or a comment included.
//
// Byte columns are deliberately NOT replaced with character columns. The CLI,
// the parser's messages and the sweep goldens all read token.Position as bytes
// and the goldens pin it, so the conversion lives here, at the protocol
// boundary, and nothing inside the lexer, parser or AST changes.
//
// A Mapper is read-only once built and safe for concurrent use. A nil Mapper
// answers every question in byte columns, which is what this server did before
// any of this existed -- a path that forgot its mapper is then wrong in the way
// it always was rather than panicking inside an editor session.
type Mapper struct {
	src string
	// lineStart[i] is the byte offset in src at which 0-based line i begins.
	// There is always an entry for line 0, and one for the empty line after a
	// trailing newline, which is a real position a cursor can sit at.
	lineStart []int
}

// NewMapper indexes src by line: one O(len(src)) pass per document version.
func NewMapper(src string) *Mapper {
	starts := make([]int, 1, strings.Count(src, "\n")+1)
	for i := 0; i < len(src); i++ {
		if src[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return &Mapper{src: src, lineStart: starts}
}

// UTF16Len is the number of UTF-16 code units s encodes to.
//
// A rune outside the basic multilingual plane needs a surrogate pair and so
// counts twice; an invalid byte decodes to one replacement character and counts
// once, which is also how a client that received the same bytes would count it.
func UTF16Len(s string) int {
	n := 0
	for _, r := range s {
		n++
		if r > 0xFFFF {
			n++
		}
	}
	return n
}

// lineText returns 0-based line i without its newline, and whether i names a
// line at all.
//
// A carriage return is left in place. The lexer counts it as a byte like any
// other, so a byte column may legitimately point at or past it, and dropping it
// here would shift every column on a CRLF line by one.
func (m *Mapper) lineText(i int) (string, bool) {
	if m == nil || i < 0 || i >= len(m.lineStart) {
		return "", false
	}
	start := m.lineStart[i]
	end := len(m.src)
	if i+1 < len(m.lineStart) {
		end = m.lineStart[i+1] - 1 // the '\n' that ended this line
	}
	return m.src[start:end], true
}

// character converts a 0-based byte column on a 0-based line to the 0-based
// UTF-16 offset the protocol wants.
//
// A column past the end of the line clamps to its end, and one that lands inside
// a rune clamps down to that rune's first byte: a position in the middle of a
// character is not a position, and cutting the string there would have counted a
// replacement character that is not in the document.
//
// A line the document does not have yields the byte column unchanged. There is
// no text to consult, and that is the answer this server gave before.
func (m *Mapper) character(line, byteCol int) lsp.UInteger {
	text, ok := m.lineText(line)
	if !ok {
		if byteCol < 0 {
			return 0
		}
		return lsp.UInteger(byteCol)
	}
	if byteCol <= 0 {
		return 0
	}
	if byteCol > len(text) {
		byteCol = len(text)
	}
	for byteCol > 0 && byteCol < len(text) && !utf8.RuneStart(text[byteCol]) {
		byteCol--
	}
	return lsp.UInteger(UTF16Len(text[:byteCol]))
}

// byteColumn is character's inverse: the 0-based byte column on a 0-based line
// that a 0-based UTF-16 offset names.
//
// An offset past the end of the line clamps to its end. An offset naming the low
// half of a surrogate pair clamps DOWN to the start of that rune, for the same
// reason as above -- half a character is not a place in the text.
func (m *Mapper) byteColumn(line int, character lsp.UInteger) int {
	text, ok := m.lineText(line)
	if !ok {
		return int(character)
	}
	want := int(character)
	if want <= 0 {
		return 0
	}
	units := 0
	for i, r := range text {
		if units == want {
			return i
		}
		next := units + 1
		if r > 0xFFFF {
			next++
		}
		if next > want {
			return i // want is this rune's low surrogate; clamp to its start
		}
		units = next
	}
	return len(text)
}

// Position converts a token.Position, whose Column is a byte count, to a
// protocol position.
//
// An invalid position yields the zero position, which is what a hand-built token
// carrying no position information has always produced.
func (m *Mapper) Position(pos token.Position) lsp.Position {
	if !pos.IsValid() {
		return lsp.Position{}
	}
	return lsp.Position{
		Line:      lsp.UInteger(pos.Line - 1),
		Character: m.character(pos.Line-1, pos.Column-1),
	}
}

// Range converts an AST range, which is two token.Positions.
func (m *Mapper) Range(rng mast.Range) lsp.Range {
	return lsp.Range{Start: m.Position(rng.Start), End: m.Position(rng.End)}
}

// PositionAt converts a 0-based line and 0-based byte column, which is what a
// scanner walking the source bytes itself has in hand rather than a
// token.Position.
func (m *Mapper) PositionAt(line, byteCol int) lsp.Position {
	if line < 0 {
		line = 0
	}
	return lsp.Position{Line: lsp.UInteger(line), Character: m.character(line, byteCol)}
}

// EndOfLine is the position one past the last character of a 0-based line,
// counted in UTF-16 units.
//
// It replaces len([]rune(line)), which is a rune count: a rune outside the basic
// multilingual plane is one rune and two UTF-16 units, so a line holding one
// ended a character short of where the client puts it.
func (m *Mapper) EndOfLine(line int) lsp.Position {
	if line < 0 {
		line = 0
	}
	text, ok := m.lineText(line)
	if !ok {
		return lsp.Position{Line: lsp.UInteger(line)}
	}
	return lsp.Position{Line: lsp.UInteger(line), Character: lsp.UInteger(UTF16Len(text))}
}

// SpanLength is the number of UTF-16 code units between two 0-based byte columns
// on one 0-based line.
//
// It is the unit a semantic token's length is measured in. The byte difference
// end-start is the wrong number on any line holding a non-ASCII character, and
// len([]rune(text)) is the wrong number for any rune outside the basic
// multilingual plane; this is right for both.
func (m *Mapper) SpanLength(line, startByteCol, endByteCol int) uint32 {
	if endByteCol <= startByteCol {
		return 0
	}
	start, end := m.character(line, startByteCol), m.character(line, endByteCol)
	if end <= start {
		return 0
	}
	return uint32(end - start)
}

// TokenPosition converts a protocol position to the 1-based line and 1-based
// byte column that token.Position and ast.Range are measured in.
func (m *Mapper) TokenPosition(pos lsp.Position) (line, column int) {
	return int(pos.Line) + 1, m.byteColumn(int(pos.Line), pos.Character) + 1
}

// ByteOffset is the offset into the document a protocol position names, and
// whether the position names one at all.
func (m *Mapper) ByteOffset(pos lsp.Position) (int, bool) {
	if m == nil {
		return 0, false
	}
	line := int(pos.Line)
	if line < 0 || line >= len(m.lineStart) {
		return 0, false
	}
	return m.lineStart[line] + m.byteColumn(line, pos.Character), true
}

// ContainsPosition reports whether an AST range covers a protocol position.
//
// The position is converted, not the range: a caller asking this is usually
// asking it of every node in the document, so converting the one position once
// is both cheaper and the only direction that cannot lose information.
func (m *Mapper) ContainsPosition(rng mast.Range, pos lsp.Position) bool {
	line, column := m.TokenPosition(pos)
	return RangeContains(rng, line, column)
}

// RangeContains reports whether rng covers a 1-based line and byte column. It
// converts nothing: both sides are already in the AST's own coordinates.
func RangeContains(rng mast.Range, line, column int) bool {
	if before(line, column, rng.Start.Line, rng.Start.Column) {
		return false
	}
	if !before(line, column, rng.End.Line, rng.End.Column) &&
		!(line == rng.End.Line && column == rng.End.Column) {
		return false
	}
	return true
}

// before reports whether one 1-based line and byte column precedes another.
// It moved here when the three conversion functions that used to live beside
// it were deleted: they equated a byte column with a UTF-16 offset, which is
// M26-LSP-027, and they are gone rather than fixed so that no call site can
// reach a conversion that does not go through a Mapper.
func before(lineA, colA, lineB, colB int) bool {
	if lineA != lineB {
		return lineA < lineB
	}
	return colA < colB
}
