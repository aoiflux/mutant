package server

import (
	"sort"
	"testing"

	localprotocol "mutant/lsp/internal/protocol"

	"github.com/tliron/glsp"
	lsp "github.com/tliron/glsp/protocol_3_16"
)

// M26-LSP-006: whole-document formatting ended its edit range at
// len([]rune(lastLine)). LSP positions count UTF-16 code units, so a character
// outside the basic multilingual plane -- one rune, two units -- put the range
// end one unit short per such character, and a client applying the edit kept
// the tail of the old last line after the formatted text. The row's own repro
// left a stray `;` on a line of its own. Format-on-save is on by default for
// Mutant documents, so this corrupted the file without being asked.
//
// The three sites the row names -- fullDocumentRange, lineDeleteRange and
// linePosition -- all count units now, since 63eb1c4. Nothing tested any of
// them, which is why this row is closed with tests rather than on the evidence.
//
// The assertion throughout is the row's own: apply the edit the way a
// spec-conforming client does, using glsp's UTF-16-aware IndexesIn, and require
// the result to be exactly the text the server said to put there. A
// full-document replacement that does not replace the full document is the
// defect, whatever the numbers in the range look like.

func formattedDocument(t *testing.T, uri lsp.DocumentUri, original string) []lsp.TextEdit {
	t.Helper()
	s := New(false)
	initializeServer(t, s)

	if _, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{URI: uri, LanguageID: "mutant", Version: 1, Text: original},
		}),
		Notify: func(string, any) {},
	}); err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	result, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentFormatting),
		Params: mustJSON(t, lsp.DocumentFormattingParams{TextDocument: lsp.TextDocumentIdentifier{URI: uri}}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("formatting returned error: %v", err)
	}
	if result == nil {
		t.Fatalf("formatting produced no result for a document that needs formatting")
	}
	edits, ok := result.([]lsp.TextEdit)
	if !ok {
		t.Fatalf("formatting result type = %T, want []TextEdit", result)
	}
	return edits
}

// applyAsASpecClientWould applies edits the way the protocol says to: offsets in
// UTF-16 code units, and non-overlapping edits applied back to front so that
// earlier offsets stay valid.
func applyAsASpecClientWould(t *testing.T, original string, edits []lsp.TextEdit) string {
	t.Helper()
	type span struct {
		start, end int
		text       string
	}
	spans := make([]span, 0, len(edits))
	for _, edit := range edits {
		start, end := edit.Range.IndexesIn(original)
		if start < 0 || end < start || end > len(original) {
			t.Fatalf("edit range %v maps to %d..%d, outside a document of %d bytes", edit.Range, start, end, len(original))
		}
		spans = append(spans, span{start, end, edit.NewText})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start > spans[j].start })

	out := original
	for _, s := range spans {
		out = out[:s.start] + s.text + out[s.end:]
	}
	return out
}

func TestFormattingReplacesTheWholeDocumentEvenWithANonBMPCharacterOnTheLastLine(t *testing.T) {
	cases := []struct {
		name     string
		original string
	}{
		{
			// The row's own repro.
			name:     "an emoji on an unterminated last line",
			original: "let a = 1;\nputln(\"done \U0001f50d\");",
		},
		{
			name:     "two emoji, so the range is two units short rather than one",
			original: "let a = 1;\nputln(\"\U0001f600\U0001f601\");",
		},
		{
			name:     "an emoji and a two-byte character together",
			original: "let a = 1;\nputln(\"café \U0001f600\");",
		},
		{
			name:     "nothing but a non-BMP string, one line",
			original: "putln(\"\U0001f600\U0001f600\U0001f600\");",
		},
		{
			name:     "a two-byte character only, which a rune count gets right",
			original: "let a = 1;\nputln(\"café\");",
		},
		{
			name:     "ascii, the control",
			original: "let a = 1;\nputln(\"done\");",
		},
		{
			name:     "crlf line endings with an emoji",
			original: "let a = 1;\r\nputln(\"\U0001f600\");",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const uri = lsp.DocumentUri("file:///format-utf16.mut")
			edits := formattedDocument(t, uri, tc.original)
			if len(edits) != 1 {
				t.Fatalf("formatting returned %d edits, want 1 whole-document replacement", len(edits))
			}

			applied := applyAsASpecClientWould(t, tc.original, edits)
			if applied != edits[0].NewText {
				t.Errorf("a whole-document replacement left text behind.\n applied: %q\n  wanted: %q\n   range: %v",
					applied, edits[0].NewText, edits[0].Range)
			}
		})
	}
}

func TestTheEndOfTheDocumentIsCountedInUnitsAndNotRunes(t *testing.T) {
	// The numbers, written down rather than derived, for the three functions the
	// row names. Each `want` is a unit count; each `runeCount` is what the
	// defect produced.
	cases := []struct {
		name      string
		text      string
		wantLine  int
		wantChar  int
		runeCount int
	}{
		{"an emoji on the last line", "let a = 1;\nputln(\"\U0001f600\");", 1, 12, 11},
		{"three emoji and nothing else", "\"\U0001f600\U0001f600\U0001f600\"", 0, 8, 5},
		{"a two-byte character, where runes happen to be right", "let a = 1;\nputln(\"café\");", 1, 14, 14},
		{"ascii", "let a = 1;\nlet b = 2;", 1, 10, 10},
		{"a trailing newline leaves an empty last line", "let a = 1;\n", 1, 0, 0},
		{"crlf: the carriage return is on the line", "let a = 1;\r\nputln(\"\U0001f600\");", 1, 12, 11},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := fullDocumentRange(tc.text)
			if int(got.End.Line) != tc.wantLine || int(got.End.Character) != tc.wantChar {
				t.Errorf("fullDocumentRange end = %d:%d, want %d:%d (a rune count gave character %d)",
					got.End.Line, got.End.Character, tc.wantLine, tc.wantChar, tc.runeCount)
			}
			if got.Start.Line != 0 || got.Start.Character != 0 {
				t.Errorf("fullDocumentRange start = %d:%d, want 0:0", got.Start.Line, got.Start.Character)
			}

			// linePosition, asked for the position one past the last line,
			// answers the same question for the range formatter.
			lines := splitLines(tc.text)
			end := linePosition(len(lines), lines)
			if int(end.Line) != tc.wantLine || int(end.Character) != tc.wantChar {
				t.Errorf("linePosition end = %d:%d, want %d:%d", end.Line, end.Character, tc.wantLine, tc.wantChar)
			}
		})
	}
}

func TestDeletingTheLastLineCoversAllOfIt(t *testing.T) {
	// lineDeleteRange is the third site. It is the last line that matters: every
	// other line is deleted by a range running to the start of the next one,
	// which needs no column arithmetic at all.
	const text = "let a = 1;\nputln(\"\U0001f600\");"
	rng, ok := lineDeleteRange(text, 1)
	if !ok {
		t.Fatal("lineDeleteRange refused the last line")
	}
	if int(rng.End.Character) != 12 {
		t.Errorf("end character = %d, want 12 (a rune count gave 11, leaving the final `;` behind)", rng.End.Character)
	}

	start, end := rng.IndexesIn(text)
	if left := text[:start] + text[end:]; left != "let a = 1;\n" {
		t.Errorf("deleting the last line left %q, want %q", left, "let a = 1;\n")
	}

	// A middle line still needs no arithmetic, and must not acquire any.
	middle, ok := lineDeleteRange("one\ntwo\nthree", 1)
	if !ok {
		t.Fatal("lineDeleteRange refused a middle line")
	}
	if middle.End.Line != 2 || middle.End.Character != 0 {
		t.Errorf("a middle line's delete range ends at %d:%d, want 2:0", middle.End.Line, middle.End.Character)
	}
}

func TestRangeFormattingEditsLandWhereTheySay(t *testing.T) {
	// The range formatter builds its own positions with linePosition, so the
	// same question is asked of it end to end: format the whole of a document
	// whose last line is unterminated and holds an emoji, apply the hunks as a
	// spec client does, and require the result to be the formatted text.
	const uri = lsp.DocumentUri("file:///format-utf16-range.mut")
	const original = "let a = 1;\n   let b  =  2;\nputln(\"\U0001f600\");"

	whole := formattedDocument(t, uri, original)
	if len(whole) != 1 {
		t.Fatalf("formatting returned %d edits, want 1", len(whole))
	}
	formatted := whole[0].NewText

	s := New(false)
	initializeServer(t, s)
	if _, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{URI: uri, LanguageID: "mutant", Version: 1, Text: original},
		}),
		Notify: func(string, any) {},
	}); err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	result, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentRangeFormatting),
		Params: mustJSON(t, lsp.DocumentRangeFormattingParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: uri},
			Range:        fullDocumentRange(original),
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("rangeFormatting returned error: %v", err)
	}
	edits, ok := result.([]lsp.TextEdit)
	if !ok || len(edits) == 0 {
		t.Fatalf("rangeFormatting result = %T with no edits; the whole document was selected", result)
	}

	if applied := applyAsASpecClientWould(t, original, edits); applied != formatted {
		t.Errorf("range formatting the whole document gave %q, want %q", applied, formatted)
	}
}

func TestTheEndOfLineHelperAgreesWithTheRange(t *testing.T) {
	// fullDocumentRange and the Mapper answer the same question from two
	// directions; they are allowed to differ only if one of them is wrong.
	for _, text := range []string{
		"let a = 1;\nputln(\"\U0001f600\");",
		"\"\U0001f600\U0001f600\"",
		"let a = 1;\nputln(\"café\");",
		"let a = 1;\r\nputln(\"\U0001f600\");",
	} {
		rng := fullDocumentRange(text)
		m := localprotocol.NewMapper(text)
		if end := m.EndOfLine(int(rng.End.Line)); end.Character != rng.End.Character {
			t.Errorf("%q: fullDocumentRange ends at character %d, Mapper.EndOfLine says %d",
				text, rng.End.Character, end.Character)
		}
	}
}
