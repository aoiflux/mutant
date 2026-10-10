package analyzer

import (
	"strings"
	"testing"
	"unicode/utf16"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// M26-SEM-010: member completion added the LSP character to the line's byte
// offset, with a comment saying "Characters are treated as bytes". LSP 3.16
// characters are UTF-16 code units, so after any non-ASCII text earlier on the
// line the offset fell short of the dot, no receiver was found, and `x.`
// completion silently stopped working.
//
// The conversion was replaced by Snapshot.ByteOffset in 63eb1c4, the commit
// that fixed the root cause M26-LSP-027, and this row was left open. Nothing
// tested member completion under UTF-16, so nothing stopped it coming back --
// which is why it is closed with these tests and not on the evidence alone.
//
// utf16_positions_test.go covers prepareRename, nodeAt, hover, semantic tokens,
// diagnostics and string-literal references. Member completion is the one
// feature it does not reach, and it is also the only one that converts the
// OTHER way: every test there turns a byte column into a character, and this
// one turns a character into a byte offset.

// The cursor is deliberately in the MIDDLE of the line, with text after it.
// At the end of a line a Mapper clamps an over-large character to the line's
// end, so the right number and the wrong one land in the same place and a probe
// written that way passes against the defect. This was measured: the first
// version of this fixture put `p.` last and could not tell the two apart.
const midLineTail = " let z = 1;"

func completionsAfterTheDot(t *testing.T, src string, character int) ([]string, bool) {
	t.Helper()
	snapshot := New().Analyze(src)
	lines := strings.Split(src, "\n")
	items, ok := snapshot.MemberCompletionsAt(lsp.Position{
		Line:      lsp.UInteger(len(lines) - 1),
		Character: lsp.UInteger(character),
	})
	labels := make([]string, 0, len(items))
	for _, item := range items {
		labels = append(labels, item.Label)
	}
	return labels, ok
}

// utf16ColumnOfTheDot is where the client's cursor is after typing the dot at
// the end of needle: the number of UTF-16 units in the line up to that point.
func utf16ColumnOfTheDot(t *testing.T, src, needle string) (utf16Col, byteCol int) {
	t.Helper()
	lines := strings.Split(src, "\n")
	line := lines[len(lines)-1]
	idx := strings.Index(line, needle)
	if idx < 0 {
		t.Fatalf("%q is not on the last line of %q", needle, src)
	}
	byteCol = idx + len(needle)
	return len(utf16.Encode([]rune(line[:byteCol]))), byteCol
}

func TestMemberCompletionFindsItsReceiverAfterNonASCIIOnTheSameLine(t *testing.T) {
	const prelude = "struct Point { x, y }\nlet p = Point{\"x\": 1, \"y\": 2};\n"

	cases := []struct {
		name   string
		needle string
		// bytesAndUnitsDiffer says the fixture can tell a byte column from a
		// UTF-16 one. The ASCII case cannot, and says so.
		bytesAndUnitsDiffer bool
	}{
		{"ascii only, the control", "let q = \"aaa\"; p.", false},
		{"two-byte characters earlier on the line", "let q = \"ééé\"; p.", true},
		{"a surrogate pair earlier on the line", "let q = \"\U0001f600\U0001f600\"; p.", true},
		{"both kinds on one line", "let q = \"é\U0001f600é\"; p.", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := prelude + tc.needle + midLineTail
			utf16Col, byteCol := utf16ColumnOfTheDot(t, src, tc.needle)

			if (utf16Col != byteCol) != tc.bytesAndUnitsDiffer {
				t.Fatalf("fixture mismatch: byte column %d, UTF-16 column %d", byteCol, utf16Col)
			}

			labels, ok := completionsAfterTheDot(t, src, utf16Col)
			if !ok {
				t.Fatalf("no member completion at the UTF-16 cursor (character %d); the byte column there is %d", utf16Col, byteCol)
			}
			if got := strings.Join(labels, ","); got != "x,y" {
				t.Errorf("completions = %v, want [x y]", labels)
			}

			if !tc.bytesAndUnitsDiffer {
				return
			}
			// What the defect received. A server that equates the two sends the
			// byte column as the character; after non-ASCII text that is a
			// larger number, so it lands past the dot and inside the trailing
			// text, where there is no member access. If this ever starts
			// succeeding, the conversion has stopped happening.
			if _, ok := completionsAfterTheDot(t, src, byteCol); ok {
				t.Errorf("the byte column %d was also accepted as a character; the two are no longer being told apart", byteCol)
			}
		})
	}
}

func TestEnumVariantCompletionAlsoConvertsTheCursor(t *testing.T) {
	// The other receiver kind the same offset feeds, so the fix is pinned for
	// both branches of MemberCompletionsAt rather than only the struct one.
	const prelude = "enum Colour { Red, Green }\n"
	const needle = "let q = \"\U0001f600\"; Colour."
	src := prelude + needle + midLineTail

	utf16Col, byteCol := utf16ColumnOfTheDot(t, src, needle)
	if utf16Col == byteCol {
		t.Fatalf("fixture cannot discriminate: both columns are %d", utf16Col)
	}

	labels, ok := completionsAfterTheDot(t, src, utf16Col)
	if !ok {
		t.Fatalf("no enum-variant completion at the UTF-16 cursor (character %d)", utf16Col)
	}
	if got := strings.Join(labels, ","); got != "Green,Red" && got != "Red,Green" {
		t.Errorf("completions = %v, want the two variants", labels)
	}
}
