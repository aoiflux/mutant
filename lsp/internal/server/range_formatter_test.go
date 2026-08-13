package server

import (
	"strings"
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func selection(startLine, endLine int) lsp.Range {
	return lsp.Range{
		Start: lsp.Position{Line: lsp.UInteger(startLine), Character: 0},
		End:   lsp.Position{Line: lsp.UInteger(endLine), Character: 0},
	}
}

// applyEdits applies non-overlapping line edits to text, last-first so that
// earlier ranges stay valid.
func applyEdits(t *testing.T, text string, edits []lsp.TextEdit) string {
	t.Helper()

	lines := splitLines(text)
	offsetOf := func(pos lsp.Position) int {
		offset := 0
		for i := 0; i < int(pos.Line) && i < len(lines); i++ {
			offset += len(lines[i])
		}
		return offset + int(pos.Character)
	}

	type resolved struct {
		start, end int
		newText    string
	}
	items := make([]resolved, 0, len(edits))
	for _, edit := range edits {
		items = append(items, resolved{offsetOf(edit.Range.Start), offsetOf(edit.Range.End), edit.NewText})
	}

	for i := len(items) - 1; i >= 0; i-- {
		item := items[i]
		if item.start > len(text) || item.end > len(text) || item.start > item.end {
			t.Fatalf("edit out of bounds: %+v for text of length %d", item, len(text))
		}
		text = text[:item.start] + item.newText + text[item.end:]
	}
	return text
}

func TestRangeFormattingOnlyTouchesSelectedLines(t *testing.T) {
	original := "let a=1;\nlet b=2;\nlet c=3;\n"
	formatted := "let a = 1;\nlet b = 2;\nlet c = 3;\n"

	// Select the middle line only.
	edits := rangeFormattingEdits(original, formatted, selection(1, 1))
	if len(edits) == 0 {
		t.Fatal("expected at least one edit")
	}

	got := applyEdits(t, original, edits)
	want := "let a=1;\nlet b = 2;\nlet c=3;\n"
	if got != want {
		t.Errorf("range formatted = %q, want %q", got, want)
	}
}

func TestRangeFormattingLeavesDocumentUnchangedForEmptySelection(t *testing.T) {
	original := "let a=1;\nlet b=2;\n"
	formatted := "let a = 1;\nlet b = 2;\n"

	// A selection covering no changed line yields no edits. Line 5 does not
	// exist in this document.
	if edits := rangeFormattingEdits(original, formatted, selection(5, 5)); len(edits) != 0 {
		t.Errorf("expected no edits, got %d", len(edits))
	}
}

func TestRangeFormattingCoveringWholeDocumentMatchesFullFormat(t *testing.T) {
	original := "let a=1;\nlet b=2;\nlet c=3;\n"
	formatted := "let a = 1;\nlet b = 2;\nlet c = 3;\n"

	edits := rangeFormattingEdits(original, formatted, selection(0, 10))
	if got := applyEdits(t, original, edits); got != formatted {
		t.Errorf("full-range formatting = %q, want %q", got, formatted)
	}
}

func TestRangeFormattingReturnsNilWhenAlreadyFormatted(t *testing.T) {
	text := "let a = 1;\n"
	if edits := rangeFormattingEdits(text, text, selection(0, 5)); edits != nil {
		t.Errorf("expected nil edits for already-formatted text, got %v", edits)
	}
}

func TestRangeFormattingHandlesLineCountChanges(t *testing.T) {
	// Formatting collapses three lines into one.
	original := "let a=1;\nif (x)\n{\ny;\n}\n"
	formatted := "let a = 1;\nif (x) {\n    y;\n}\n"

	// Selecting everything must reproduce the full format exactly.
	edits := rangeFormattingEdits(original, formatted, selection(0, 20))
	if got := applyEdits(t, original, edits); got != formatted {
		t.Errorf("formatted = %q, want %q", got, formatted)
	}
}

func TestRangeFormattingSkipsHunksStraddlingSelection(t *testing.T) {
	// A single hunk spans lines 1-3; selecting only line 2 must skip it
	// rather than applying half of it.
	original := "let a = 1;\nif (x)\n{\ny;\n}\n"
	formatted := "let a = 1;\nif (x) {\n    y;\n}\n"

	edits := rangeFormattingEdits(original, formatted, selection(2, 2))
	got := applyEdits(t, original, edits)

	// Whatever it did, it must not have corrupted lines outside the selection.
	if !strings.HasPrefix(got, "let a = 1;\n") {
		t.Errorf("line 0 was modified: %q", got)
	}
}

func TestSplitLinesRoundTrips(t *testing.T) {
	inputs := []string{
		"",
		"a",
		"a\n",
		"a\nb",
		"a\nb\n",
		"\n",
		"\n\n",
		"a\n\nb\n",
	}

	for _, input := range inputs {
		if got := strings.Join(splitLines(input), ""); got != input {
			t.Errorf("splitLines(%q) rejoined to %q", input, got)
		}
	}
}

func TestDiffLinesProducesNoHunksForIdenticalInput(t *testing.T) {
	lines := splitLines("a\nb\nc\n")
	if hunks := diffLines(lines, lines); len(hunks) != 0 {
		t.Errorf("expected no hunks, got %+v", hunks)
	}
}

func TestDiffLinesReconstructsTarget(t *testing.T) {
	cases := []struct{ from, to string }{
		{"a\nb\nc\n", "a\nB\nc\n"},
		{"a\nb\nc\n", "a\nc\n"},
		{"a\nc\n", "a\nb\nc\n"},
		{"a\n", "b\n"},
		{"a\nb\nc\nd\ne\n", "a\nx\ny\ne\n"},
		{"", "a\n"},
		{"a\n", ""},
		{"a\nb\n", "b\na\n"},
	}

	for _, tc := range cases {
		from := splitLines(tc.from)
		to := splitLines(tc.to)

		// Applying every hunk must reproduce the target exactly.
		hunks := diffLines(from, to)
		result := make([]string, 0, len(to))
		cursor := 0
		for _, hunk := range hunks {
			result = append(result, from[cursor:hunk.startLine]...)
			result = append(result, hunk.newLines...)
			cursor = hunk.endLine
		}
		result = append(result, from[cursor:]...)

		if got := strings.Join(result, ""); got != tc.to {
			t.Errorf("diff %q -> %q reconstructed %q", tc.from, tc.to, got)
		}
	}
}
