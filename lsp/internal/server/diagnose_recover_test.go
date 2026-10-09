package server

import (
	"strings"
	"testing"

	"mutant/lsp/internal/analyzer"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// TestAPanickingLintRuleDoesNotEndTheProcess drives the recover in diagnose.
//
// It is here because the exposure was structural rather than about one rule.
// analyzer.Diagnostics is called on jsonrpc2's single reader goroutine and
// nothing on that path recovered -- not this server, and neither glsp nor
// jsonrpc2 contains a recover() at all -- so a panic in any one of the
// thirty-odd lint rules ended the process instead of failing a request. The
// editor's server vanished mid-keystroke, and because the workspace scan
// parses every .mut it finds, a file that provoked one took it down again on
// every start. M26-LEX-010 was a panic of that kind and removing it removed
// one source, not the exposure.
func TestAPanickingLintRuleDoesNotEndTheProcess(t *testing.T) {
	original := runLintSet
	t.Cleanup(func() { runLintSet = original })

	runLintSet = func(*analyzer.Snapshot, analyzer.LintConfig) []lsp.Diagnostic {
		panic("a lint rule walked into a nil")
	}

	s := &Server{}
	// A document with a real syntax error in it, so the test can also check
	// that the author keeps the diagnostics least likely to be the cause.
	snapshot := analyzer.New().Analyze("let x = ;")

	var diagnostics []lsp.Diagnostic
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("diagnose did not recover: %v", r)
			}
		}()
		diagnostics = s.diagnose(snapshot)
	}()

	var reported bool
	for _, d := range diagnostics {
		if strings.Contains(d.Message, "stopped analysing this file after an internal error") {
			reported = true
			if !strings.Contains(d.Message, "a lint rule walked into a nil") {
				t.Errorf("the diagnostic should carry what the panic said, got %q", d.Message)
			}
		}
	}
	if !reported {
		t.Errorf("a recovered panic must be reported, not swallowed: a silent recovery makes a "+
			"broken rule look like a clean file. diagnostics = %v", messages(diagnostics))
	}

	// The parse errors survive the panic, which is the reason they are
	// collected inside the protected region rather than fetched from the
	// recover.
	var parseReported bool
	for _, d := range diagnostics {
		if d.Source != nil && *d.Source == "mutant-parser" {
			parseReported = true
		}
	}
	if !parseReported {
		t.Errorf("a rule panicking must not cost the author their syntax errors, got %v",
			messages(diagnostics))
	}
}

// TestDiagnoseIsTheOrdinaryPathWhenNothingPanics keeps the seam honest: with
// the real lint set in place, diagnose is analyzer.Diagnostics and nothing else.
func TestDiagnoseIsTheOrdinaryPathWhenNothingPanics(t *testing.T) {
	s := &Server{}
	snapshot := analyzer.New().Analyze("let x = 1; x = 2;")

	got := s.diagnose(snapshot)
	want := analyzer.Diagnostics(snapshot, s.currentLintConfig())
	if len(got) != len(want) {
		t.Fatalf("diagnose returned %d diagnostics, Diagnostics returned %d", len(got), len(want))
	}
	for i := range got {
		if got[i].Message != want[i].Message {
			t.Errorf("diagnostic %d: %q, want %q", i, got[i].Message, want[i].Message)
		}
	}
}

func messages(diagnostics []lsp.Diagnostic) []string {
	out := make([]string, 0, len(diagnostics))
	for _, d := range diagnostics {
		out = append(out, d.Message)
	}
	return out
}
