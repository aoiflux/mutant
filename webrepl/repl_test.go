package webrepl

import (
	"strings"
	"testing"
)

func evalInput(t *testing.T, repl *REPL, input string) string {
	t.Helper()
	out, err := repl.Eval(input)
	if err != nil {
		t.Fatalf("Eval(%q) unexpected error: %v", input, err)
	}
	return out
}

func TestEvalArraysHashesAndIndexing(t *testing.T) {
	repl := New()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "array index", input: "[10, 20, 30][1]", expected: "20"},
		{name: "hash index", input: "{\"x\": 99}[\"x\"]", expected: "99"},
		{name: "array out of bounds is null", input: "[1][3]", expected: ""},
		{name: "missing hash key is null", input: "{\"x\": 1}[\"y\"]", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalInput(t, repl, tt.input)
			if got != tt.expected {
				t.Fatalf("Eval(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestEvalCollectionBuiltins(t *testing.T) {
	repl := New()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "len string", input: "len(\"abc\")", expected: "3"},
		{name: "len array", input: "len([1, 2, 3])", expected: "3"},
		{name: "first", input: "first([7, 8, 9])", expected: "7"},
		{name: "last", input: "last([7, 8, 9])", expected: "9"},
		{name: "rest", input: "rest([7, 8, 9])", expected: "[8, 9]"},
		{name: "push", input: "push([7, 8], 9)", expected: "[7, 8, 9]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalInput(t, repl, tt.input)
			if got != tt.expected {
				t.Fatalf("Eval(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestEvalTextBuiltins(t *testing.T) {
	repl := New()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "text_contains true", input: "text_contains(\"mutant rocks\", \"rocks\")", expected: "true"},
		{name: "text_index", input: "text_index(\"abcdef\", \"cd\")", expected: "2"},
		{name: "text_count", input: "text_count(\"aaaa\", \"aa\")", expected: "2"},
		{name: "text_split", input: "text_split(\"a,b,c\", \",\")", expected: "[a, b, c]"},
		{name: "text_replace", input: "text_replace(\"hello world\", \"world\", \"mutant\")", expected: "hello mutant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalInput(t, repl, tt.input)
			if got != tt.expected {
				t.Fatalf("Eval(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestEvalCallErrors(t *testing.T) {
	repl := New()

	_, err := repl.Eval("unknown_fn(1)")
	if err == nil {
		t.Fatal("expected error for unknown function")
	}
	if !strings.Contains(err.Error(), "unknown function: unknown_fn") {
		t.Fatalf("unexpected error for unknown function: %v", err)
	}

	_, err = repl.Eval("len(1)")
	if err == nil {
		t.Fatal("expected error for invalid len argument")
	}
	if !strings.Contains(err.Error(), "argument to len not supported") {
		t.Fatalf("unexpected len error: %v", err)
	}
}

func TestSupportedSyntaxSummaryIncludesExpandedFeatures(t *testing.T) {
	summary := SupportedSyntaxSummary()

	for _, want := range []string{
		"arrays, hashes, indexing",
		"function calls for browser-safe builtins",
		"builtins: len, first, last, rest, push, text_* core set",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary %q missing %q", summary, want)
		}
	}
}

func TestEvalHelpCommands(t *testing.T) {
	repl := New()

	out, err := repl.Eval(":help docs")
	if err != nil {
		t.Fatalf("Eval(:help docs) unexpected error: %v", err)
	}
	if !strings.Contains(out, "https://mudocs.aoiflux.xyz") {
		t.Fatalf("expected docs URL in :help output, got %q", out)
	}

	out, err = repl.Eval("help(\"builtins\")")
	if err != nil {
		t.Fatalf("Eval(help) unexpected error: %v", err)
	}
	if !strings.Contains(out, "Mutant builtins") {
		t.Fatalf("expected builtin listing in help output, got %q", out)
	}
}

func TestCompletionCandidatesIncludeBuiltinsAndSymbols(t *testing.T) {
	repl := New()
	_, _ = repl.Eval("let custom_symbol = 42;")

	candidates := repl.CompletionCandidates("cu", "supported")
	joined := strings.Join(candidates, "\n")
	if !strings.Contains(joined, "custom_symbol") {
		t.Fatalf("completion candidates missing session symbol: %v", candidates)
	}

	builtinCandidates := repl.CompletionCandidates("text_", "supported")
	joinedBuiltins := strings.Join(builtinCandidates, "\n")
	if !strings.Contains(joinedBuiltins, "text_split") {
		t.Fatalf("completion candidates missing supported builtin: %v", builtinCandidates)
	}
}

func TestCompletionCandidatesForLineHelpContext(t *testing.T) {
	repl := New()

	topicCandidates := repl.CompletionCandidatesForLine(":help bu", "supported")
	if len(topicCandidates) == 0 || topicCandidates[0] != "builtins" {
		t.Fatalf("expected builtins topic candidate, got %v", topicCandidates)
	}

	modeCandidates := repl.CompletionCandidatesForLine("help(\"builtins\", \"a", "supported")
	if len(modeCandidates) == 0 || modeCandidates[0] != "\"all" {
		t.Fatalf("expected quoted all mode candidate, got %v", modeCandidates)
	}
}
