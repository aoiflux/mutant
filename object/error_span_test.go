package object

import (
	"strings"
	"testing"
)

// The underline is the whole point of carrying an end position, so its column
// arithmetic gets pinned rather than eyeballed.
func TestSpanUnderlineCoversTheRequestedColumns(t *testing.T) {
	const text = "let total = sum / count;"

	tests := []struct {
		name     string
		startCol int
		endCol   int
		want     string
	}{
		{
			name:     "a span underlines every column it covers",
			startCol: 13,
			endCol:   24,
			want:     strings.Repeat(" ", 12) + strings.Repeat("^", 11),
		},
		{
			name:     "no end position degrades to a single caret",
			startCol: 13,
			endCol:   0,
			want:     strings.Repeat(" ", 12) + "^",
		},
		{
			name:     "an end at the start is treated as no end",
			startCol: 5,
			endCol:   5,
			want:     strings.Repeat(" ", 4) + "^",
		},
		{
			name:     "a span running past the line stops at its end",
			startCol: 21,
			endCol:   400,
			want:     strings.Repeat(" ", 20) + "^^^^",
		},
		{
			name:     "the first column needs no leading space",
			startCol: 1,
			endCol:   4,
			want:     "^^^",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := SpanUnderline(text, test.startCol, test.endCol)
			if got != test.want {
				t.Errorf("underline\n got %q\nwant %q", got, test.want)
			}
		})
	}
}

// Tabs are copied through rather than counted as one column, because the
// terminal that renders the code renders the caret row the same way. Replacing
// them with spaces is what makes carets drift on tab-indented source.
func TestSpanUnderlineKeepsTabsInTheLeadingWhitespace(t *testing.T) {
	got := SpanUnderline("\t\treturn a / b;", 10, 15)
	want := "\t\t" + strings.Repeat(" ", 7) + "^^^^^"

	if got != want {
		t.Errorf("underline\n got %q\nwant %q", got, want)
	}
}

// A start column past the end of the line cannot underline anything real; it
// must still produce a row rather than panicking on the failure path.
func TestSpanUnderlineToleratesAnOutOfRangeStart(t *testing.T) {
	if got := SpanUnderline("short", 99, 120); got == "" {
		t.Error("an out-of-range start produced no underline row")
	}
	if got := SpanUnderline("", 1, 5); got != "^" {
		t.Errorf("empty line underline = %q, want %q", got, "^")
	}
}

func TestErrorSnippetQuotesTheLineAndUnderlinesTheSpan(t *testing.T) {
	err := &Error{
		Message:    "integer division by zero",
		File:       "prog.mut",
		Line:       7,
		Column:     12,
		EndLine:    7,
		EndColumn:  17,
		SourceLine: "    return a / b;",
	}

	snippet := err.Snippet()
	if !strings.Contains(snippet, "7 |     return a / b;") {
		t.Errorf("snippet does not quote the source line:\n%s", snippet)
	}
	if !strings.Contains(snippet, "^^^^^") {
		t.Errorf("snippet does not underline the span:\n%s", snippet)
	}
}

// An error with no source line -- every error in a stripped build -- renders
// nothing rather than an empty gutter.
func TestErrorSnippetIsEmptyWithoutASourceLine(t *testing.T) {
	err := &Error{Message: "boom", Line: 7, Column: 1}
	if got := err.Snippet(); got != "" {
		t.Errorf("snippet without source = %q, want empty", got)
	}
}

// Inspect carries the position and deliberately not the stack: a caught error
// printed in a loop would otherwise emit a full traceback per iteration.
func TestErrorInspectCarriesPositionButNotTheStack(t *testing.T) {
	err := &Error{
		Message:    "boom",
		File:       "prog.mut",
		Line:       7,
		Column:     12,
		SourceLine: "    return a / b;",
		Stack:      []string{"at f (prog.mut:7:12)", "at <main> (prog.mut:9:1)"},
	}

	inspected := err.Inspect()
	if !strings.Contains(inspected, "at prog.mut:7:12") {
		t.Errorf("Inspect lost the position: %q", inspected)
	}
	if strings.Contains(inspected, "<main>") || strings.Contains(inspected, "^") {
		t.Errorf("Inspect leaked the stack or snippet: %q", inspected)
	}
	if !strings.Contains(err.Traceback(), "<main>") {
		t.Errorf("Traceback lost a frame: %q", err.Traceback())
	}
}
