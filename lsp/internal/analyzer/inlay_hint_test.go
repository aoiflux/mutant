package analyzer

import (
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func wideRange() lsp.Range {
	return lsp.Range{Start: lsp.Position{Line: 0, Character: 0}, End: lsp.Position{Line: 1000, Character: 0}}
}

func TestInlayHintsUserFunctionParameters(t *testing.T) {
	src := "let add = fn(left, right) { return left + right; };\n" +
		"add(1, 2);\n"
	s := New().Analyze(src)
	hints := s.InlayHints(wideRange())

	labels := make([]string, 0, len(hints))
	for _, h := range hints {
		labels = append(labels, h.Label)
	}
	if !containsLabel(labels, "left:") || !containsLabel(labels, "right:") {
		t.Fatalf("expected left:/right: parameter hints, got %v", labels)
	}
}

func TestInlayHintsBuiltinParameters(t *testing.T) {
	// push(array, value) is a documented builtin with named params.
	src := "let xs = [1, 2];\npush(xs, 3);\n"
	s := New().Analyze(src)
	hints := s.InlayHints(wideRange())
	if len(hints) == 0 {
		t.Fatal("expected inlay hints for builtin call push(xs, 3)")
	}
	// At least the second argument should carry a name hint.
	foundNamed := false
	for _, h := range hints {
		if h.Label != "" && h.Kind != nil {
			foundNamed = true
		}
	}
	if !foundNamed {
		t.Fatalf("expected a named parameter hint, got %+v", hints)
	}
}

func TestInlayHintsRangeFiltering(t *testing.T) {
	src := "let f = fn(a) { return a; };\n" + // line 0
		"f(1);\n" + // line 1
		"f(2);\n" // line 2
	s := New().Analyze(src)

	// Only line 1 requested: hints from the line-2 call must be excluded.
	only := s.InlayHints(lsp.Range{
		Start: lsp.Position{Line: 1, Character: 0},
		End:   lsp.Position{Line: 1, Character: 100},
	})
	for _, h := range only {
		if h.Position.Line != 1 {
			t.Fatalf("hint outside requested range: line %d", h.Position.Line)
		}
	}
	if len(only) == 0 {
		t.Fatal("expected at least one hint on line 1")
	}
}

func TestInlayHintsSuppressSameNameArgument(t *testing.T) {
	// The argument identifier equals the parameter name -> no hint (noise).
	src := "let g = fn(value) { return value; };\nlet value = 1;\ng(value);\n"
	s := New().Analyze(src)
	hints := s.InlayHints(wideRange())
	for _, h := range hints {
		if h.Label == "value:" {
			t.Fatalf("expected the same-name argument hint to be suppressed, got %+v", hints)
		}
	}
}

func containsLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}
