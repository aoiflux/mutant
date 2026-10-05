package analyzer

import (
	"strings"
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// These are the end-to-end tests for M26-LSP-027: the language server measured
// Position.character in bytes where LSP 3.16 defines it as an offset in UTF-16
// code units, so every position-based feature pointed at the wrong place on any
// line holding a non-ASCII character.
//
// The trigger is not a non-ASCII identifier. A non-ASCII character anywhere
// earlier on the line does it -- in these fixtures it is inside a string
// literal, which is the ordinary case: 18 of the .mut files shipped in this
// repository carry non-ASCII in a string or a comment.
//
// Every fixture here derives the cursor from the source text rather than
// hard-coding a column, and then asserts that the byte column and the UTF-16
// offset actually differ. Without that assertion a fixture that drifted back to
// pure ASCII would still pass while testing nothing.

const (
	// LATIN SMALL LETTER E WITH ACUTE: 2 UTF-8 bytes, 1 UTF-16 unit.
	testEAcute = "é"
	// GRINNING FACE: 4 UTF-8 bytes, 2 UTF-16 units -- a surrogate pair.
	testGrin = "\U0001f600"
)

// cursorFixture is a one-line document plus the two different numbers that name
// the same place in it.
type cursorFixture struct {
	src       string // the whole document
	line      int    // 0-based line the needle is on
	needle    string
	byteCol   int // 0-based byte column, which is what the lexer counts
	character int // 0-based UTF-16 offset, which is what a client sends
}

func newCursorFixture(t *testing.T, lead, needle, tail string) cursorFixture {
	t.Helper()
	line := lead + needle + tail
	src := "let " + needle + " = 1;\n" + line + "\n"

	byteCol := strings.Index(line, needle)
	if byteCol < 0 {
		t.Fatalf("the needle %q is not in %q", needle, line)
	}
	character := int(utf16Len(line[:byteCol]))

	if byteCol == character {
		t.Fatalf("this fixture tests nothing: the byte column and the UTF-16 offset "+
			"of %q in %q are both %d, so it would pass on the unfixed code",
			needle, line, byteCol)
	}
	return cursorFixture{src: src, line: 1, needle: needle, byteCol: byteCol, character: character}
}

func (f cursorFixture) cursor() lsp.Position {
	return lsp.Position{Line: lsp.UInteger(f.line), Character: lsp.UInteger(f.character)}
}

// fixtures returns the same shape with a 2-byte rune and with a surrogate pair,
// because the two drift from a byte column by different amounts.
func fixtures(t *testing.T) map[string]cursorFixture {
	t.Helper()
	return map[string]cursorFixture{
		"after a 2-byte rune in a string": newCursorFixture(t,
			`let out = "`+testEAcute+`" + `, "target", ";"),
		"after a surrogate pair in a string": newCursorFixture(t,
			`let out = "`+testGrin+`" + `, "target", ";"),
		"after several non-ASCII characters": newCursorFixture(t,
			`let out = "`+testEAcute+testGrin+testEAcute+`" + `, "target", ";"),
	}
}

// A comment is deliberately NOT a fixture here, and the reason is worth
// recording because the row's own wording invites one. A line comment runs to
// the end of its line, so no identifier can follow a non-ASCII character that
// sits inside one -- there is nothing after it to resolve. A comment still
// shifts positions WITHIN itself, which the converter's own table test covers;
// it cannot shift a position in code, because no code follows it on that line.

// TestPrepareRenameFindsTheIdentifierUnderAUTF16Cursor is the row's named
// regression test.
//
// The server advertises RenameProvider, and a rename returns TextEdits built
// from these ranges, so accepting one applied the edit at the wrong offset in
// the user's file. On the unfixed code the cursor below is read one byte per
// extra UTF-8 byte too far left, which lands before the identifier starts, and
// PrepareRename returns false instead of naming it.
func TestPrepareRenameFindsTheIdentifierUnderAUTF16Cursor(t *testing.T) {
	for name, f := range fixtures(t) {
		t.Run(name, func(t *testing.T) {
			s := New().Analyze(f.src)

			placeholder, rng, ok := s.PrepareRename(f.cursor())
			if !ok {
				t.Fatalf("no identifier found at line %d character %d; the byte column "+
					"there is %d, which is where the unfixed code looked",
					f.line, f.character, f.byteCol)
			}
			if placeholder != f.needle {
				t.Errorf("placeholder %q, want %q", placeholder, f.needle)
			}

			// And the range handed back must be in the client's units too, or
			// the rename edit lands in the wrong place even once it is found.
			converted := s.Range(rng)
			if int(converted.Start.Character) != f.character {
				t.Errorf("range starts at character %d, want %d (byte column %d)",
					converted.Start.Character, f.character, f.byteCol)
			}
			wantEnd := f.character + len(f.needle)
			if int(converted.End.Character) != wantEnd {
				t.Errorf("range ends at character %d, want %d",
					converted.End.Character, wantEnd)
			}
		})
	}
}

func TestNodeAtFindsTheNodeUnderAUTF16Cursor(t *testing.T) {
	for name, f := range fixtures(t) {
		t.Run(name, func(t *testing.T) {
			s := New().Analyze(f.src)
			_, rng, ok := s.NodeAt(f.cursor())
			if !ok {
				t.Fatalf("no node at line %d character %d", f.line, f.character)
			}
			if rng.Start.Column-1 != f.byteCol {
				t.Errorf("node starts at byte column %d, want %d",
					rng.Start.Column-1, f.byteCol)
			}
		})
	}
}

func TestHoverResolvesUnderAUTF16Cursor(t *testing.T) {
	for name, f := range fixtures(t) {
		t.Run(name, func(t *testing.T) {
			s := New().Analyze(f.src)
			if _, _, ok := s.HoverText(f.cursor()); !ok {
				t.Errorf("nothing to hover at line %d character %d", f.line, f.character)
			}
		})
	}
}

// TestASemanticTokenStartAndLengthAreInUTF16Units covers the surface the row
// does not name. A token carries a start column AND a length, and both are
// measured in the protocol's units: the start was a byte column, and the length
// was either the byte difference end-start or a rune count, neither of which is
// the number a client adds to the start.
func TestASemanticTokenStartAndLengthAreInUTF16Units(t *testing.T) {
	for name, f := range fixtures(t) {
		t.Run(name, func(t *testing.T) {
			s := New().Analyze(f.src)

			var found bool
			for _, tok := range s.semanticTokenList() {
				if int(tok.line) != f.line || int(tok.start) != f.character {
					continue
				}
				found = true
				if int(tok.length) != len(f.needle) {
					t.Errorf("token length %d, want %d", tok.length, len(f.needle))
				}
			}
			if !found {
				t.Errorf("no semantic token starts at line %d character %d; "+
					"byte column %d is where the unfixed code put it",
					f.line, f.character, f.byteCol)
			}
		})
	}
}

// TestALengthCountsUnitsAndNotRunes isolates the surrogate-pair half of the
// token length, which a rune count gets wrong on its own.
func TestALengthCountsUnitsAndNotRunes(t *testing.T) {
	src := `let s = "a` + testGrin + `b";` + "\n"
	s := New().Analyze(src)

	// A string literal's token length is measured over TokenLiteral, which is
	// the value WITHOUT its quotes: `a<pair>b` is 3 runes and 4 UTF-16 units,
	// because the pair needs two of them. The rune count is what this returned
	// before, and it is the smaller number.
	const wantUnits = 4
	body := "a" + testGrin + "b"
	if got := utf16Len(body); got != wantUnits {
		t.Fatalf("the fixture body is %d units, want %d", got, wantUnits)
	}
	if got := len([]rune(body)); got != 3 {
		t.Fatalf("the fixture body is %d runes, want 3 -- the rune count is the defect", got)
	}

	var lengths []uint32
	for _, tok := range s.semanticTokenList() {
		if tok.line == 0 && tok.start == 8 {
			lengths = append(lengths, tok.length)
		}
	}
	if len(lengths) == 0 {
		t.Fatal("no semantic token at the string literal")
	}
	for _, got := range lengths {
		if got != wantUnits {
			t.Errorf("token length %d, want %d (3 would be the rune count)", got, wantUnits)
		}
	}
}

// TestADiagnosticRangeIsInUTF16Units checks the outbound direction on the
// feature a user sees first. An underline one unit per extra UTF-8 byte too far
// right is the visible form of this defect.
func TestADiagnosticRangeIsInUTF16Units(t *testing.T) {
	// An undefined identifier on a line that already holds a non-ASCII
	// character. This rule and not the unused-declaration one, because this is
	// the one DefaultLintConfig has on -- checked with a probe, not assumed.
	line := `let out = "` + testEAcute + `"; let y = unknownName;`
	src := line + "\n"
	byteCol := strings.Index(line, "unknownName")
	character := int(utf16Len(line[:byteCol]))
	if byteCol == character {
		t.Fatal("this fixture tests nothing: the two columns agree")
	}

	s := New().Analyze(src)
	var matched bool
	for _, d := range Diagnostics(s, DefaultLintConfig()) {
		if d.Range.Start.Line != 0 {
			continue
		}
		if int(d.Range.Start.Character) == character {
			matched = true
		}
		if int(d.Range.Start.Character) == byteCol && byteCol != character {
			t.Errorf("a diagnostic starts at character %d, which is the BYTE column; "+
				"the UTF-16 offset is %d (%q)", byteCol, character, d.Message)
		}
		// And it has to end where the identifier ends, in the same units.
		if int(d.Range.Start.Character) == character {
			if want := character + len("unknownName"); int(d.Range.End.Character) != want {
				t.Errorf("the diagnostic ends at character %d, want %d",
					d.Range.End.Character, want)
			}
		}
	}
	if !matched {
		t.Errorf("no diagnostic starts at character %d; diagnostics on this line: %d",
			character, len(Diagnostics(s, DefaultLintConfig())))
	}
}

// TestAStringLiteralRefIsInUTF16Units covers document links, whose range is
// trimmed by one unit at each end to drop the quotes. That trim is only correct
// once the values it adjusts are already in the right units.
func TestAStringLiteralRefIsInUTF16Units(t *testing.T) {
	line := `let a = "` + testEAcute + `"; let p = "mod/thing.mut";`
	src := line + "\n"
	byteCol := strings.Index(line, `"mod/thing.mut"`)
	character := int(utf16Len(line[:byteCol]))
	if byteCol == character {
		t.Fatal("this fixture tests nothing: the two columns agree")
	}

	s := New().Analyze(src)
	for _, ref := range s.StringLiteralRefs() {
		if ref.Value != "mod/thing.mut" {
			continue
		}
		// The quotes are trimmed, so the range starts one unit in.
		if want := character + 1; int(ref.Range.Start.Character) != want {
			t.Errorf("link starts at character %d, want %d",
				ref.Range.Start.Character, want)
		}
		if want := character + 1 + len("mod/thing.mut"); int(ref.Range.End.Character) != want {
			t.Errorf("link ends at character %d, want %d", ref.Range.End.Character, want)
		}
		return
	}
	t.Error("the path literal produced no document link")
}

// TestAnASCIIDocumentIsUnaffected is the compatibility guarantee, stated as a
// test rather than left as an argument: on an ASCII line a byte column and a
// UTF-16 offset are the same number, so this whole change cannot have moved any
// position in an ASCII document. Every other fixture in this package is ASCII.
func TestAnASCIIDocumentIsUnaffected(t *testing.T) {
	src := "let target = 1;\nlet out = 2 + target;\n"
	s := New().Analyze(src)

	line := "let out = 2 + target;"
	byteCol := strings.Index(line, "target")
	if got := int(utf16Len(line[:byteCol])); got != byteCol {
		t.Fatalf("on an ASCII line the two columns must agree: %d and %d", got, byteCol)
	}

	pos := lsp.Position{Line: 1, Character: lsp.UInteger(byteCol)}
	placeholder, rng, ok := s.PrepareRename(pos)
	if !ok || placeholder != "target" {
		t.Fatalf("PrepareRename gave (%q, %v); want (\"target\", true)", placeholder, ok)
	}
	converted := s.Range(rng)
	if int(converted.Start.Character) != byteCol {
		t.Errorf("range starts at character %d, want %d", converted.Start.Character, byteCol)
	}
	if int(converted.End.Character) != byteCol+len("target") {
		t.Errorf("range ends at character %d, want %d",
			converted.End.Character, byteCol+len("target"))
	}
}
