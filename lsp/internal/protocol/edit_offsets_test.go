package protocol

import (
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// EditOffsets is the inbound half of this package: where in the text a change
// the client sent is to be applied. It exists because glsp's own
// Range.IndexesIn answers offset 0 for any position past the end of the
// content, which made a position outside the document indistinguishable from
// the very start of it (M26-LSP-004).
//
// The rule EditOffsets adds over ByteOffset is deliberately narrow: a line past
// the last line is the end of the document. A query must NOT have that rule --
// "which node is under the cursor" has no answer for a line that is not in the
// text, and clamping it would answer about the last line instead of saying no
// -- so the two live in two functions rather than in one with a flag.
//
// at() is the helper positions_test.go already uses for a position.

func rangeOf(sl, sc, el, ec int) lsp.Range {
	return lsp.Range{Start: at(sl, sc), End: at(el, ec)}
}

func TestAnEditOffsetClampsTheWayTheProtocolSaysTo(t *testing.T) {
	cases := []struct {
		name string
		src  string
		at   lsp.Position
		want int
		why  string
	}{
		{"the start of an empty document", "", at(0, 0), 0, ""},
		{"the start of a line", "abc\ndef", at(1, 0), 4, ""},
		{"inside a line", "abc\ndef", at(1, 2), 6, ""},
		{"the exact end of a line", "abc\ndef", at(0, 3), 3, ""},
		{"a character past the end of a line", "abc\ndef", at(0, 9), 3,
			"LSP 3.16: a character greater than the line length defaults back to the line length"},
		{"a character past the end of the last line", "abc", at(0, 99), 3, ""},
		{"the empty line after a trailing newline", "abc\n", at(1, 0), 4, ""},
		{"a line past the last line", "abc\ndef", at(5, 0), 7,
			"clients spell 'the end of the document' as (lineCount, 0)"},
		{"a line past the last line, with a character too", "abc\ndef", at(5, 40), 7, ""},
		{"a carriage return is a byte on its line", "abc\r\ndef", at(0, 4), 4,
			"the line is abc\\r: four units, four bytes, and unit 4 is after the carriage return"},
		{"after a two-byte character", "lét = 1", at(0, 3), 4,
			"l, e-acute and t are three UTF-16 units and four bytes, so unit 3 is byte 4"},
		{"after a surrogate pair", "\U0001f600x", at(0, 2), 4,
			"the emoji is two UTF-16 units and four bytes, so unit 2 is byte 4"},
		{"inside a surrogate pair", "\U0001f600x", at(0, 1), 0,
			"half a character is not a place in the text: it clamps down to the rune's start"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := NewMapper(tc.src).EditOffset(tc.at)
			if !ok {
				t.Fatalf("EditOffset refused the position; an edit always has somewhere to go")
			}
			if got != tc.want {
				t.Errorf("offset = %d, want %d. %s", got, tc.want, tc.why)
			}
		})
	}
}

func TestAQueryAndAnEditDisagreeAboutALineThatIsNotThere(t *testing.T) {
	// The one difference between the two, pinned so that nobody unifies them by
	// making ByteOffset clamp: every caller asking about the cursor would then
	// get an answer about the last line where it used to get none.
	const src = "abc\ndef"
	m := NewMapper(src)

	if _, ok := m.ByteOffset(at(5, 0)); ok {
		t.Error("ByteOffset answered for a line the document does not have")
	}
	got, ok := m.EditOffset(at(5, 0))
	if !ok {
		t.Fatal("EditOffset refused a line past the end; a client says 'the end of the document' that way")
	}
	if got != len(src) {
		t.Errorf("EditOffset = %d, want %d (the end of the document)", got, len(src))
	}
}

func TestEditOffsetsRefusesARangeItCannotMeanAnythingBy(t *testing.T) {
	const src = "let a = 1;\nlet b = 2;"
	if _, _, ok := EditOffsets(src, rangeOf(0, 8, 0, 2)); ok {
		t.Error("a start after its own end was accepted; the protocol orders a range's ends")
	}
	if _, _, ok := EditOffsets(src, rangeOf(1, 4, 0, 0)); ok {
		t.Error("a start on a later line than its end was accepted")
	}

	var nilMapper *Mapper
	if _, ok := nilMapper.EditOffset(at(0, 0)); ok {
		t.Error("a nil Mapper answered an edit offset; there is no text to apply an edit to")
	}
}

func TestEditOffsetsSpansWhatTheClientMeant(t *testing.T) {
	// The two reproduced failures of M26-LSP-004, as ranges.
	cases := []struct {
		name       string
		src        string
		rng        lsp.Range
		wantStart  int
		wantEnd    int
		glspAnswer string
	}{
		{
			name: "an insert past the end of the only line", src: "abc",
			rng: rangeOf(0, 10, 0, 10), wantStart: 3, wantEnd: 3,
			glspAnswer: "0..0, so the insert landed at the start of the document",
		},
		{
			name: "a range ending at (lineCount, 0)", src: "let a = 1;\nlet b = 2;",
			rng: rangeOf(1, 0, 2, 0), wantStart: 11, wantEnd: 21,
			glspAnswer: "11..0, an end before its start, which the caller could only refuse",
		},
		{
			name: "the whole document, the way a formatter asks for it", src: "let a = 1;\nputln(\"\U0001f600\");",
			rng: rangeOf(0, 0, 1, 12), wantStart: 0, wantEnd: 25,
			glspAnswer: "the same: this range is in the document and glsp reads it correctly",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := EditOffsets(tc.src, tc.rng)
			if !ok {
				t.Fatalf("EditOffsets refused the range; glsp answered %s", tc.glspAnswer)
			}
			if start != tc.wantStart || end != tc.wantEnd {
				t.Errorf("offsets = %d..%d, want %d..%d (glsp answered %s)", start, end, tc.wantStart, tc.wantEnd, tc.glspAnswer)
			}
			if end > len(tc.src) {
				t.Errorf("end %d is past the content (%d bytes); the store slices with these", end, len(tc.src))
			}
		})
	}
}

func TestEveryOffsetEditOffsetsReturnsIsInsideTheContent(t *testing.T) {
	// The store slices a string with these two numbers inside a language
	// server, where a panic ends the editor's session rather than one request.
	// That the offsets are always usable is the contract, so it is measured
	// over a spread of positions rather than asserted in a comment.
	sources := []string{
		"",
		"\n",
		"abc",
		"abc\n",
		"abc\r\ndef",
		"let a = \"\U0001f600\"; b",
		"lét = 1;\n\U0001f600\n",
	}
	for _, src := range sources {
		for line := 0; line < 6; line++ {
			for character := 0; character < 24; character++ {
				start, end, ok := EditOffsets(src, rangeOf(line, character, line, character))
				if !ok {
					t.Fatalf("EditOffsets(%q, %d:%d) refused a well-ordered range", src, line, character)
				}
				if start < 0 || end < start || end > len(src) {
					t.Fatalf("EditOffsets(%q, %d:%d) = %d..%d, outside 0..%d", src, line, character, start, end, len(src))
				}
			}
		}
	}
}
