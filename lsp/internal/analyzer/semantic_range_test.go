package analyzer

import (
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func equalUint(a, b []lsp.UInteger) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestSemanticTokensRangeDataMatchesFullWhenCoveringAllLines(t *testing.T) {
	src := "let a = 1;\nlet b = 2;\nlet c = 3;\n"
	s := New().Analyze(src)
	full := s.SemanticTokensData()
	if len(full) == 0 {
		t.Fatal("expected full semantic tokens")
	}
	rng := s.SemanticTokensRangeData(lsp.Range{
		Start: lsp.Position{Line: 0, Character: 0},
		End:   lsp.Position{Line: 100, Character: 0},
	})
	if !equalUint(full, rng) {
		t.Fatalf("range over all lines should equal full\nfull=%v\nrng =%v", full, rng)
	}
}

func TestSemanticTokensRangeDataExcludesOutOfRange(t *testing.T) {
	src := "let a = 1;\nlet b = 2;\nlet c = 3;\n"
	s := New().Analyze(src)
	full := s.SemanticTokensData()

	line0 := s.SemanticTokensRangeData(lsp.Range{
		Start: lsp.Position{Line: 0, Character: 0},
		End:   lsp.Position{Line: 0, Character: 100},
	})
	if len(line0) == 0 {
		t.Fatal("expected tokens on line 0")
	}
	if len(line0) >= len(full) {
		t.Fatalf("single-line range (%d) should be a strict subset of full (%d)", len(line0), len(full))
	}

	empty := s.SemanticTokensRangeData(lsp.Range{
		Start: lsp.Position{Line: 50, Character: 0},
		End:   lsp.Position{Line: 60, Character: 0},
	})
	if len(empty) != 0 {
		t.Fatalf("expected no tokens beyond content, got %d entries", len(empty))
	}
}
