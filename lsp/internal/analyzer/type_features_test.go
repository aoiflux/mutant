package analyzer

import (
	"strings"
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func TestHoverShowsInferredType(t *testing.T) {
	s := New().Analyze("let count = 5;\ncount;\n")
	// hover on the usage `count` (line 1)
	text, _, ok := s.HoverText(lsp.Position{Line: 1, Character: 0})
	if !ok {
		t.Fatal("expected hover text")
	}
	if !strings.Contains(text, ": int") {
		t.Fatalf("hover = %q, want it to contain ': int'", text)
	}
}

func TestHoverShowsStructType(t *testing.T) {
	s := New().Analyze("struct Point { x; };\nlet p = Point{x: 1};\np;\n")
	text, _, ok := s.HoverText(lsp.Position{Line: 2, Character: 0})
	if !ok {
		t.Fatal("expected hover text")
	}
	if !strings.Contains(text, ": Point") {
		t.Fatalf("hover = %q, want it to contain ': Point'", text)
	}
}

func TestHoverNoTypeForUnknown(t *testing.T) {
	s := New().Analyze("let x = mystery_call();\nx;\n")
	text, _, ok := s.HoverText(lsp.Position{Line: 1, Character: 0})
	if !ok {
		t.Fatal("expected hover text")
	}
	if strings.Contains(text, " : ") {
		t.Fatalf("hover for unknown type should not show ' : ', got %q", text)
	}
}

func TestCompletionDetailCarriesType(t *testing.T) {
	s := New().Analyze("let total = 42;\n\n")
	items := s.CompletionItemsAt(lsp.Position{Line: 1, Character: 0})
	var found bool
	for _, it := range items {
		if it.Label == "total" {
			found = true
			if it.Detail == nil || *it.Detail != "int" {
				t.Fatalf("completion detail for total = %v, want \"int\"", it.Detail)
			}
		}
	}
	if !found {
		t.Fatal("expected a completion item for total")
	}
}

func TestInlayTypeHintOnLetBinding(t *testing.T) {
	s := New().Analyze("let count = 5;\nlet mystery = unknown_fn();\n")
	hints := s.InlayHints(lsp.Range{
		Start: lsp.Position{Line: 0, Character: 0},
		End:   lsp.Position{Line: 100, Character: 0},
	})

	var haveInt, haveMystery bool
	for _, h := range hints {
		if h.Label == ": int" {
			haveInt = true
		}
		// `mystery` has an unknown type -> no type hint for it.
		if strings.HasPrefix(h.Label, ":") && h.Position.Line == 1 {
			haveMystery = true
		}
	}
	if !haveInt {
		t.Fatalf("expected a ': int' type hint for count, got %+v", hints)
	}
	if haveMystery {
		t.Fatal("expected no type hint for the untyped `mystery` binding")
	}
}
