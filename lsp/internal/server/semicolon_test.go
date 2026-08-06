package server

import (
	"testing"

	"mutant/lsp/internal/analyzer"

	"github.com/tliron/glsp"
	lsp "github.com/tliron/glsp/protocol_3_16"
)

func openDocument(t *testing.T, s *Server, uri lsp.DocumentUri, text string) {
	t.Helper()

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        uri,
				LanguageID: "mutant",
				Version:    1,
				Text:       text,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
}

func semicolonDiagnostics(t *testing.T, src string) []lsp.Diagnostic {
	t.Helper()

	snapshot := analyzer.New().Analyze(src)
	out := make([]lsp.Diagnostic, 0, 2)
	for _, diagnostic := range analyzer.Diagnostics(snapshot, analyzer.DefaultLintConfig()) {
		if diagnostic.Source != nil && *diagnostic.Source == analyzer.DiagnosticSourceFormat {
			out = append(out, diagnostic)
		}
	}
	return out
}

func TestMissingSemicolonProducesDiagnostic(t *testing.T) {
	diagnostics := semicolonDiagnostics(t, "let x = 5")
	if len(diagnostics) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d: %+v", len(diagnostics), diagnostics)
	}

	diagnostic := diagnostics[0]
	if diagnostic.Message != "missing ';' at end of statement" {
		t.Errorf("message = %q", diagnostic.Message)
	}
	if diagnostic.Severity == nil || *diagnostic.Severity != lsp.DiagnosticSeverityWarning {
		t.Errorf("severity = %v, want warning", diagnostic.Severity)
	}
	// Widened so the editor renders it, rather than a zero-width marker.
	if diagnostic.Range.Start == diagnostic.Range.End {
		t.Errorf("range %+v is zero-width and would render invisibly", diagnostic.Range)
	}
}

func TestRedundantSemicolonProducesDiagnostic(t *testing.T) {
	diagnostics := semicolonDiagnostics(t, "let x = 5;;")
	if len(diagnostics) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d: %+v", len(diagnostics), diagnostics)
	}
	if diagnostics[0].Message != "redundant ';'" {
		t.Errorf("message = %q", diagnostics[0].Message)
	}
}

func TestWellFormedSourceHasNoSemicolonDiagnostics(t *testing.T) {
	src := "let x = 5;\nlet f = fn() {\n    return x;\n};\nif (x) {\n    f();\n}\n"
	if diagnostics := semicolonDiagnostics(t, src); len(diagnostics) != 0 {
		t.Errorf("expected no diagnostics, got %+v", diagnostics)
	}
}

func TestSemicolonRuleCanBeDisabled(t *testing.T) {
	config := analyzer.DefaultLintConfig()
	config.Semicolon = analyzer.LintSeverityOff

	snapshot := analyzer.New().Analyze("let x = 5")
	for _, diagnostic := range analyzer.Diagnostics(snapshot, config) {
		if diagnostic.Source != nil && *diagnostic.Source == analyzer.DiagnosticSourceFormat {
			t.Errorf("rule is off but produced %+v", diagnostic)
		}
	}
}

// The quick fix has to actually repair the source, not merely appear.
func TestMissingSemicolonQuickFixRepairsSource(t *testing.T) {
	src := "let x = 5"
	diagnostics := semicolonDiagnostics(t, src)
	if len(diagnostics) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(diagnostics))
	}

	actions := semicolonQuickFixes("file:///t.mut", diagnostics[0])
	if len(actions) != 1 {
		t.Fatalf("expected 1 quick fix, got %d", len(actions))
	}
	if actions[0].Title != "Insert missing ';'" {
		t.Errorf("title = %q", actions[0].Title)
	}

	edits := actions[0].Edit.Changes["file:///t.mut"]
	repaired := applyEdits(t, src, edits)
	if repaired != "let x = 5;" {
		t.Fatalf("repaired = %q, want %q", repaired, "let x = 5;")
	}
	if remaining := semicolonDiagnostics(t, repaired); len(remaining) != 0 {
		t.Errorf("repaired source still reports %+v", remaining)
	}
}

func TestRedundantSemicolonQuickFixRepairsSource(t *testing.T) {
	src := "let x = 5;;"
	diagnostics := semicolonDiagnostics(t, src)
	if len(diagnostics) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(diagnostics))
	}

	actions := semicolonQuickFixes("file:///t.mut", diagnostics[0])
	if len(actions) != 1 {
		t.Fatalf("expected 1 quick fix, got %d", len(actions))
	}
	if actions[0].Title != "Remove redundant ';'" {
		t.Errorf("title = %q", actions[0].Title)
	}

	edits := actions[0].Edit.Changes["file:///t.mut"]
	repaired := applyEdits(t, src, edits)
	if repaired != "let x = 5;" {
		t.Fatalf("repaired = %q, want %q", repaired, "let x = 5;")
	}
	if remaining := semicolonDiagnostics(t, repaired); len(remaining) != 0 {
		t.Errorf("repaired source still reports %+v", remaining)
	}
}

func TestParseStrictFormattingDefaultsToTrue(t *testing.T) {
	cases := []struct {
		name     string
		settings any
		want     bool
	}{
		{"nil settings", nil, true},
		{"unrelated settings", map[string]any{"other": 1}, true},
		{"explicit true", map[string]any{"strictFormatting": true}, true},
		{"explicit false", map[string]any{"strictFormatting": false}, false},
		{"nested under mutant", map[string]any{"mutant": map[string]any{"strictFormatting": false}}, false},
		{"wrong type ignored", map[string]any{"strictFormatting": "no"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseStrictFormatting(tc.settings); got != tc.want {
				t.Errorf("parseStrictFormatting = %v, want %v", got, tc.want)
			}
		})
	}
}

// With strict formatting disabled the server must decline to format at all,
// rather than fall back to some looser style.
func TestStrictFormattingDisabledSuppressesFormatting(t *testing.T) {
	s := New(false)
	initializeServer(t, s)
	s.setStrictFormatting(false)

	uri := lsp.DocumentUri("file:///strict-off.mut")
	original := "let    x=1;"
	openDocument(t, s, uri, original)

	edits, err := s.formatting(nil, &lsp.DocumentFormattingParams{
		TextDocument: lsp.TextDocumentIdentifier{URI: uri},
	})
	if err != nil {
		t.Fatalf("formatting returned error: %v", err)
	}
	if len(edits) != 0 {
		t.Errorf("expected no edits when strict formatting is off, got %+v", edits)
	}

	rangeEdits, err := s.rangeFormatting(nil, &lsp.DocumentRangeFormattingParams{
		TextDocument: lsp.TextDocumentIdentifier{URI: uri},
		Range:        selection(0, 0),
	})
	if err != nil {
		t.Fatalf("rangeFormatting returned error: %v", err)
	}
	if len(rangeEdits) != 0 {
		t.Errorf("expected no range edits when strict formatting is off, got %+v", rangeEdits)
	}
}

func TestStrictFormattingEnabledByDefault(t *testing.T) {
	s := New(false)
	if !s.strictFormattingEnabled() {
		t.Error("strict formatting should default to enabled")
	}
}

func TestRangeFormattingThroughServer(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	uri := lsp.DocumentUri("file:///range.mut")
	original := "let a=1;\nlet b=2;\n"
	openDocument(t, s, uri, original)

	edits, err := s.rangeFormatting(nil, &lsp.DocumentRangeFormattingParams{
		TextDocument: lsp.TextDocumentIdentifier{URI: uri},
		Range:        selection(0, 0),
	})
	if err != nil {
		t.Fatalf("rangeFormatting returned error: %v", err)
	}
	if len(edits) == 0 {
		t.Fatal("expected edits for the selected line")
	}

	got := applyEdits(t, original, edits)
	want := "let a = 1;\nlet b=2;\n"
	if got != want {
		t.Errorf("range formatted = %q, want %q", got, want)
	}
}
