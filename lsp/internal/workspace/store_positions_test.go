package workspace

import (
	"errors"
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// M26-LSP-004. Two defects with one cause: the store asked glsp's
// Range.IndexesIn where a change goes, and that answers offset 0 for any
// position past the end of the content. An insert past the end of the last line
// therefore landed at the START of the document, and a range ending at
// (lineCount, 0) came back as an end before its start, which could only be
// refused -- after which the store kept the old text at the old version while
// the client moved on, and every later change was applied to text neither side
// had.
//
// Every test here uses only wire types and the store's own API, so each one
// compiles unchanged against the tree that has the defect.

const testURI = lsp.DocumentUri("file:///store-positions.mut")

func at(line, character int) lsp.Position {
	return lsp.Position{Line: lsp.UInteger(line), Character: lsp.UInteger(character)}
}

func over(sl, sc, el, ec int) *lsp.Range {
	r := lsp.Range{Start: at(sl, sc), End: at(el, ec)}
	return &r
}

func edited(t *testing.T, original string, changes ...any) (string, error) {
	t.Helper()
	s := NewStore()
	s.Open(testURI, 1, original)
	doc, err := s.Update(testURI, 2, changes)
	if err != nil {
		return "", err
	}
	if doc == nil {
		t.Fatalf("Update returned no document and no error")
	}
	return doc.Text, nil
}

func TestACharacterPastTheEndOfALineClampsToItsEnd(t *testing.T) {
	// LSP 3.16, textDocument/didChange: "If the character value is greater than
	// the line length it defaults back to the line length." The client that
	// sends this means the end of the line, not the start of the file.
	cases := []struct {
		name   string
		src    string
		change *lsp.Range
		text   string
		want   string
		defect string
	}{
		{
			name:   "insert far past the end of the only line",
			src:    "abc",
			change: over(0, 10, 0, 10),
			text:   "X",
			want:   "abcX",
			defect: "Xabc",
		},
		{
			name:   "insert one past the end of the only line",
			src:    "abc",
			change: over(0, 3, 0, 3),
			text:   "X",
			want:   "abcX",
			defect: "abcX",
		},
		{
			name:   "replace from past the end",
			src:    "let a = 1;",
			change: over(0, 40, 0, 60),
			text:   " // done",
			want:   "let a = 1; // done",
			defect: " // donelet a = 1;",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := edited(t, tc.src, lsp.TextDocumentContentChangeEvent{Range: tc.change, Text: tc.text})
			if err != nil {
				t.Fatalf("Update returned error: %v", err)
			}
			if got != tc.want {
				t.Errorf("text = %q, want %q (the defect gave %q)", got, tc.want, tc.defect)
			}
		})
	}
}

func TestALinePastTheLastLineIsTheEndOfTheDocument(t *testing.T) {
	// Several clients express "to the end of the document" as (lineCount, 0).
	// There is no such line, and the store has to read it as the end rather
	// than as offset zero.
	got, err := edited(t, "let a = 1;\nlet b = 2;",
		lsp.TextDocumentContentChangeEvent{Range: over(1, 0, 2, 0), Text: "let b = 3;"})
	if err != nil {
		t.Fatalf("Update returned error: %v (the defect answered 'invalid change range: 11..0')", err)
	}
	if want := "let a = 1;\nlet b = 3;"; got != want {
		t.Errorf("text = %q, want %q", got, want)
	}
}

func TestAnEditAfterANonBMPCharacterLandsWhereTheClientPutIt(t *testing.T) {
	// The discriminating fixture: an emoji is one rune, two UTF-16 units and
	// four bytes, so the three units disagree by different amounts and a test
	// written on ASCII could not tell them apart.
	//
	//   l e t _ a _ = _ "  <emoji>   " ;  _  b
	//   0 1 2 3 4 5 6 7 8  9..12    13 14 15 16   bytes, len 17
	//   0 1 2 3 4 5 6 7 8  9,10     11 12 13 14   UTF-16 units, len 15
	//
	// So the `b` occupies UTF-16 units 14..15 and bytes 16..17. A store reading
	// the character as a byte column would cut at 14, which is the semicolon.
	const src = "let a = \"\U0001f600\"; b"
	got, err := edited(t, src, lsp.TextDocumentContentChangeEvent{Range: over(0, 14, 0, 15), Text: "c"})
	if err != nil {
		t.Fatalf("Update returned error: %v", err)
	}
	if want := "let a = \"\U0001f600\"; c"; got != want {
		t.Errorf("text = %q, want %q", got, want)
	}
}

func TestACarriageReturnIsNotCountedTwice(t *testing.T) {
	// The store slices the text it was given, carriage returns and all, so the
	// line index has to be built over the real bytes. A conversion that
	// normalised the line endings first would be short one byte per line.
	const src = "let a = 1;\r\nlet b = 2;\r\n"
	got, err := edited(t, src, lsp.TextDocumentContentChangeEvent{Range: over(1, 10, 1, 10), Text: " // two"})
	if err != nil {
		t.Fatalf("Update returned error: %v", err)
	}
	if want := "let a = 1;\r\nlet b = 2; // two\r\n"; got != want {
		t.Errorf("text = %q, want %q", got, want)
	}
}

func TestAnOrdinaryInRangeEditIsUnchanged(t *testing.T) {
	// The population check. The fix is a clamp, and a clamp that moved any
	// position a client already sends correctly would break every keystroke in
	// the editor that ships -- VS Code sends in-range positions and never
	// reaches the defect at all.
	cases := []struct {
		name   string
		src    string
		change *lsp.Range
		text   string
		want   string
	}{
		{"replace in the middle of a line", "abcdef", over(0, 2, 0, 4), "ZZ", "abZZef"},
		{"insert at the start", "abc", over(0, 0, 0, 0), "X", "Xabc"},
		{"delete a whole line", "one\ntwo\nthree", over(1, 0, 2, 0), "", "one\nthree"},
		{"insert at the end of a middle line", "one\ntwo\nthree", over(1, 3, 1, 3), "!", "one\ntwo!\nthree"},
		{"replace across two lines", "one\ntwo\nthree", over(0, 1, 2, 2), "X", "oXree"},
		{"a whole-document change", "anything", nil, "fresh", "fresh"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := edited(t, tc.src, lsp.TextDocumentContentChangeEvent{Range: tc.change, Text: tc.text})
			if err != nil {
				t.Fatalf("Update returned error: %v", err)
			}
			if got != tc.want {
				t.Errorf("text = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAStartAfterItsOwnEndIsRefused(t *testing.T) {
	// The protocol orders a range's ends. A start past its end is a malformed
	// request, not a position to guess at, and guessing is what would put the
	// two copies out of step without either side being told.
	s := NewStore()
	s.Open(testURI, 1, "let a = 1;")
	if _, err := s.Update(testURI, 2, []any{
		lsp.TextDocumentContentChangeEvent{Range: over(0, 8, 0, 2), Text: "X"},
	}); err == nil {
		t.Fatal("Update accepted a range whose start is after its end")
	}
}

func TestARefusedChangeLeavesTheVersionWhereItWas(t *testing.T) {
	// The second half of the row, and the one that loses work: the store used
	// to keep the old text at the old version, didChange dropped the error
	// because a notification has nowhere to put one, and the next version's
	// changes were applied to stale text AND ACCEPTED. From then on the server
	// and the client disagreed about the file for as long as it stayed open.
	s := NewStore()
	s.Open(testURI, 1, "let a = 1;\nlet b = 2;")

	// Something the store cannot apply. An unknown payload type is the one
	// refusal the clamp cannot remove, which is why it is used here.
	if _, err := s.Update(testURI, 2, []any{"not a change event"}); err == nil {
		t.Fatal("Update accepted an unsupported change payload")
	}

	after, ok := s.Snapshot(testURI)
	if !ok {
		t.Fatal("the document is gone")
	}
	if after.Version != 1 {
		t.Errorf("version = %d after a refused change, want 1: a version the text never reached is what let the next change through", after.Version)
	}
	if !after.Desynced {
		t.Error("the document is not marked desynced, so nothing stops the next change being applied to text the client does not have")
	}

	// The next version's incremental change must be refused rather than
	// applied, and must not quietly become the truth.
	_, err := s.Update(testURI, 3, []any{
		lsp.TextDocumentContentChangeEvent{Range: over(1, 10, 1, 10), Text: " putln(b);"},
	})
	if !errors.Is(err, ErrDocumentDesynced) {
		t.Fatalf("v3 error = %v, want ErrDocumentDesynced", err)
	}
	stale, _ := s.Snapshot(testURI)
	if stale.Text != "let a = 1;\nlet b = 2;" {
		t.Errorf("text = %q, want it untouched", stale.Text)
	}
	if stale.Version != 1 {
		t.Errorf("version = %d, want 1", stale.Version)
	}
}

func TestAWholeDocumentChangePutsTheStoreBackInStep(t *testing.T) {
	// The protocol has no request that asks a client to send a document again,
	// so a desynced store cannot recover on its own. What it can do is accept
	// the one kind of change that needs nothing from the text it replaces.
	for _, name := range []string{"the dedicated whole-document event", "a change event with no range"} {
		t.Run(name, func(t *testing.T) {
			s := NewStore()
			s.Open(testURI, 1, "let a = 1;")
			if _, err := s.Update(testURI, 2, []any{"not a change event"}); err == nil {
				t.Fatal("Update accepted an unsupported change payload")
			}

			var whole any = lsp.TextDocumentContentChangeEventWhole{Text: "let a = 9;"}
			if name == "a change event with no range" {
				whole = lsp.TextDocumentContentChangeEvent{Text: "let a = 9;"}
			}
			doc, err := s.Update(testURI, 3, []any{whole})
			if err != nil {
				t.Fatalf("a whole-document change was refused: %v", err)
			}
			if doc.Text != "let a = 9;" {
				t.Errorf("text = %q, want %q", doc.Text, "let a = 9;")
			}
			if doc.Desynced {
				t.Error("still desynced after a whole-document change")
			}
			if doc.Version != 3 {
				t.Errorf("version = %d, want 3", doc.Version)
			}

			// And an ordinary incremental change works again.
			if _, err := s.Update(testURI, 4, []any{
				lsp.TextDocumentContentChangeEvent{Range: over(0, 8, 0, 9), Text: "1"},
			}); err != nil {
				t.Fatalf("an incremental change after resynchronising: %v", err)
			}
			back, _ := s.Snapshot(testURI)
			if back.Text != "let a = 1;" {
				t.Errorf("text = %q, want %q", back.Text, "let a = 1;")
			}
		})
	}
}

func TestReopeningADocumentClearsTheDesync(t *testing.T) {
	s := NewStore()
	s.Open(testURI, 1, "let a = 1;")
	if _, err := s.Update(testURI, 2, []any{"not a change event"}); err == nil {
		t.Fatal("Update accepted an unsupported change payload")
	}
	doc := s.Open(testURI, 5, "let a = 2;")
	if doc.Desynced {
		t.Error("a freshly opened document is desynced; didOpen carries the whole text")
	}
}

func TestAStaleVersionIsStillJustIgnored(t *testing.T) {
	// Unchanged behaviour, pinned because the new flag sits next to it: an
	// out-of-order notification is not a desync, it is a duplicate.
	s := NewStore()
	s.Open(testURI, 7, "let a = 1;")
	_, err := s.Update(testURI, 7, []any{
		lsp.TextDocumentContentChangeEvent{Range: over(0, 0, 0, 0), Text: "X"},
	})
	if !errors.Is(err, ErrStaleDocumentVersion) {
		t.Fatalf("error = %v, want ErrStaleDocumentVersion", err)
	}
	doc, _ := s.Snapshot(testURI)
	if doc.Desynced {
		t.Error("a stale version marked the document desynced; it carries no information about the text")
	}
	if doc.Text != "let a = 1;" {
		t.Errorf("text = %q, want it untouched", doc.Text)
	}
}
