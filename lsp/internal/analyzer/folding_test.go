package analyzer

import "testing"

// hasFold reports whether some folding range spans exactly [startLine, endLine]
// (zero-based).
func hasFold(ranges []foldSpan, startLine, endLine uint32) bool {
	for _, r := range ranges {
		if r.start == startLine && r.end == endLine {
			return true
		}
	}
	return false
}

type foldSpan struct {
	start, end uint32
	kind       string
}

func foldSpans(t *testing.T, src string) []foldSpan {
	t.Helper()
	s := New().Analyze(src)
	raw := s.FoldingRanges()
	out := make([]foldSpan, 0, len(raw))
	for _, r := range raw {
		k := ""
		if r.Kind != nil {
			k = *r.Kind
		}
		out = append(out, foldSpan{start: r.StartLine, end: r.EndLine, kind: k})
	}
	return out
}

func TestFoldingRangesFoldsBlocksAndBodies(t *testing.T) {
	// line 0: let add = fn(a, b) {
	// line 1:     return a + b;
	// line 2: };
	src := "let add = fn(a, b) {\n    return a + b;\n};\n"
	spans := foldSpans(t, src)
	if !hasFold(spans, 0, 2) {
		t.Fatalf("expected a fold spanning lines 0..2 for the fn body, got %+v", spans)
	}
}

func TestFoldingRangesStructAndArrayLiteral(t *testing.T) {
	// struct on lines 0..3, array literal on lines 5..8
	src := "struct Point {\n    x;\n    y;\n};\n" +
		"\n" +
		"let nums = [\n    1,\n    2\n];\n"
	spans := foldSpans(t, src)
	if !hasFold(spans, 0, 3) {
		t.Fatalf("expected struct body fold 0..3, got %+v", spans)
	}
	if !hasFold(spans, 5, 8) {
		t.Fatalf("expected array literal fold 5..8, got %+v", spans)
	}
}

func TestFoldingRangesCommentRun(t *testing.T) {
	// three consecutive comment lines 0..2, then code
	src := "// first\n// second\n// third\nlet x = 1;\n"
	spans := foldSpans(t, src)
	found := false
	for _, r := range spans {
		if r.start == 0 && r.end == 2 && r.kind == "comment" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a comment fold 0..2 (kind comment), got %+v", spans)
	}
}

func TestFoldingRangesSingleLineDoesNotFold(t *testing.T) {
	// A one-line block must not produce a fold.
	src := "let f = fn() { return 1; };\n"
	spans := foldSpans(t, src)
	for _, r := range spans {
		if r.start == r.end {
			t.Fatalf("degenerate single-line fold produced: %+v", spans)
		}
	}
}
