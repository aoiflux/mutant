package builtin

import (
	"strings"
	"testing"
)

func TestRenderReplHelpOverview(t *testing.T) {
	output := RenderReplHelp("", ReplHelpOptions{})
	if !strings.Contains(output, "Mutant REPL help") {
		t.Fatalf("overview help missing heading: %q", output)
	}
	if !strings.Contains(output, MutantDocsURL) {
		t.Fatalf("overview help missing docs URL: %q", output)
	}
}

func TestRenderReplHelpBuiltinsSupportedMode(t *testing.T) {
	supported := map[string]struct{}{
		BuiltinNameLen: {},
	}
	output := RenderReplHelp("builtins", ReplHelpOptions{Mode: "supported", SupportedBuiltins: supported})
	if !strings.Contains(output, "- len") {
		t.Fatalf("expected supported builtin in output: %q", output)
	}
	if strings.Contains(output, "- fs_read") {
		t.Fatalf("unexpected unsupported builtin in supported-mode output: %q", output)
	}
}

func TestRenderReplHelpBuiltinDetailUnsupportedMarker(t *testing.T) {
	supported := map[string]struct{}{
		BuiltinNameLen: {},
	}
	output := RenderReplHelp(BuiltinNameFsRead, ReplHelpOptions{Mode: "all", SupportedBuiltins: supported})
	if !strings.Contains(output, "unsupported in browser/wasm REPL") {
		t.Fatalf("expected unsupported marker for wasm in builtin detail: %q", output)
	}
}

func TestReplCompletionCandidatesIncludesPrefixMatches(t *testing.T) {
	candidates := ReplCompletionCandidates("help", ReplHelpOptions{Symbols: []string{"helper_symbol"}})
	joined := strings.Join(candidates, "\n")
	if !strings.Contains(joined, "help()") {
		t.Fatalf("completion output missing help() candidate: %v", candidates)
	}
	if !strings.Contains(joined, "helper_symbol") {
		t.Fatalf("completion output missing session symbol: %v", candidates)
	}
}

func TestReplCompletionCandidatesForLineHelpTopicContext(t *testing.T) {
	candidates := ReplCompletionCandidatesForLine(":help bu", ReplHelpOptions{})
	if len(candidates) == 0 {
		t.Fatal("expected :help topic candidates")
	}
	if candidates[0] != "builtins" {
		t.Fatalf("expected builtins to be top candidate, got %v", candidates)
	}
}

func TestReplCompletionCandidatesForLineHelpCallModes(t *testing.T) {
	candidates := ReplCompletionCandidatesForLine("help(\"builtins\", \"a", ReplHelpOptions{})
	if len(candidates) == 0 {
		t.Fatal("expected help mode candidates")
	}
	if candidates[0] != "\"all" {
		t.Fatalf("expected quoted all mode candidate, got %v", candidates)
	}
}

func TestReplCompletionCandidatesRankingPrefersSymbols(t *testing.T) {
	candidates := ReplCompletionCandidates("he", ReplHelpOptions{Symbols: []string{"hello_var"}})
	if len(candidates) == 0 {
		t.Fatal("expected candidates for prefix 'he'")
	}
	if candidates[0] != "hello_var" {
		t.Fatalf("expected symbol to be ranked first, got %v", candidates)
	}
}
