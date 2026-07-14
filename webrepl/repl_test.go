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
		{name: "pop", input: "pop([7, 8, 9])", expected: "[7, 8]"},
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

func TestEvalForLoopsAndAssignments(t *testing.T) {
	repl := New()

	t.Run("for loop over len(items) prints each element", func(t *testing.T) {
		got := evalInput(t, repl, `let items = ["bytecode", "sandbox", "signing", "lsp"]; for (let i = 0; i < len(items); i = i + 1) { putln(items[i]); }`)
		want := "bytecode\nsandbox\nsigning\nlsp"
		if got != want {
			t.Fatalf("for loop output = %q, want %q", got, want)
		}
	})

	t.Run("break exits loop", func(t *testing.T) {
		got := evalInput(t, repl, `for (let i = 0; i < 10; i = i + 1) { if (i == 3) { break; }; putln(i); }`)
		want := "0\n1\n2"
		if got != want {
			t.Fatalf("break loop output = %q, want %q", got, want)
		}
	})

	t.Run("continue skips current iteration", func(t *testing.T) {
		got := evalInput(t, repl, `for (let i = 0; i < 5; i = i + 1) { if (i == 2) { continue; }; putln(i); }`)
		want := "0\n1\n3\n4"
		if got != want {
			t.Fatalf("continue loop output = %q, want %q", got, want)
		}
	})
}

func TestEvalFunctionStructEnumAndFloatParity(t *testing.T) {
	repl := New()

	t.Run("function literal call", func(t *testing.T) {
		got := evalInput(t, repl, `let inc = fn(x) { x + 1; }; inc(41)`)
		if got != "42" {
			t.Fatalf("function literal call = %q, want %q", got, "42")
		}
	})

	t.Run("function return exits early", func(t *testing.T) {
		got := evalInput(t, repl, `let f = fn(x) { if (x > 0) { return x; }; x + 10; }; f(5)`)
		if got != "5" {
			t.Fatalf("function return = %q, want %q", got, "5")
		}
	})

	t.Run("closure captures outer scope", func(t *testing.T) {
		got := evalInput(t, repl, `let seed = 10; let add = fn(x) { x + seed; }; add(7)`)
		if got != "17" {
			t.Fatalf("closure output = %q, want %q", got, "17")
		}
	})

	t.Run("float literal and arithmetic", func(t *testing.T) {
		got := evalInput(t, repl, `1.5 + 2.25`)
		if got != "3.750000" {
			t.Fatalf("float arithmetic = %q, want %q", got, "3.750000")
		}
	})

	t.Run("struct literal and field access", func(t *testing.T) {
		got := evalInput(t, repl, `struct Point { x; y; }; let p = Point { x: 1, y: 2 }; p.x`)
		if got != "1" {
			t.Fatalf("struct field access = %q, want %q", got, "1")
		}
	})

	t.Run("struct field assignment", func(t *testing.T) {
		got := evalInput(t, repl, `let p = Point { x: 1, y: 2 }; p.x = 9; p.x`)
		if got != "9" {
			t.Fatalf("struct field assignment = %q, want %q", got, "9")
		}
	})

	t.Run("enum variant access", func(t *testing.T) {
		got := evalInput(t, repl, `enum Color { Red, Green, Blue }; Color.Red`)
		if got != "Color.Red(0)" {
			t.Fatalf("enum access = %q, want %q", got, "Color.Red(0)")
		}
	})
}

func TestEvalPrintBuiltins(t *testing.T) {
	repl := New()

	t.Run("putln returns buffered output", func(t *testing.T) {
		got := evalInput(t, repl, `putln("hello", "world")`)
		if got != "hello world" {
			t.Fatalf("Eval(putln) = %q, want %q", got, "hello world")
		}
	})

	t.Run("putf and expression share output", func(t *testing.T) {
		got := evalInput(t, repl, `putf("count="); len([1, 2, 3])`)
		if got != "count=3" {
			t.Fatalf("Eval(putf...) = %q, want %q", got, "count=3")
		}
	})

	t.Run("multiple putln calls preserve lines", func(t *testing.T) {
		got := evalInput(t, repl, `putln("one"); putln("two")`)
		if got != "one\ntwo" {
			t.Fatalf("Eval(multiple putln) = %q, want %q", got, "one\ntwo")
		}
	})
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

func TestEvalExtendedDataBuiltins(t *testing.T) {
	repl := New()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "json stringify", input: `json_stringify({"name": "mutant", "count": 3})`, expected: `{"count":3,"name":"mutant"}`},
		{name: "regex match", input: `regex_match("foo.+", "foobar")`, expected: `true`},
		{name: "regex find all", input: `regex_find_all("a.", "abacad")`, expected: `[ab, ac, ad]`},
		{name: "regex capture groups", input: `regex_capture_groups("(foo)(bar)", "xxfoobarxx")`, expected: `[foobar, foo, bar]`},
		{name: "text levenshtein", input: `text_levenshtein("kitten", "sitting")`, expected: `3`},
		{name: "text similarity", input: `text_similarity("mutant", "mutants")`, expected: `0.857143`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalInput(t, repl, tt.input)
			if got != tt.expected {
				t.Fatalf("Eval(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}

	t.Run("json parse fields", func(t *testing.T) {
		got := evalInput(t, repl, `json_parse(json_stringify({"ok": true, "items": [1, 2]}))["ok"]`)
		if got != "true" {
			t.Fatalf("json_parse field lookup = %q, want %q", got, "true")
		}

		got = evalInput(t, repl, `json_parse(json_stringify({"ok": true, "items": [1, 2]}))["items"][1]`)
		if got != "2" {
			t.Fatalf("json_parse nested array lookup = %q, want %q", got, "2")
		}
	})

	t.Run("text fuzzy find fields", func(t *testing.T) {
		got := evalInput(t, repl, `text_fuzzy_find("mutnt", ["alpha", "mutant", "beta"])["found"]`)
		if got != "true" {
			t.Fatalf("text_fuzzy_find found = %q, want %q", got, "true")
		}

		got = evalInput(t, repl, `text_fuzzy_find("mutnt", ["alpha", "mutant", "beta"])["match"]`)
		if got != "mutant" {
			t.Fatalf("text_fuzzy_find match = %q, want %q", got, "mutant")
		}
	})

	t.Run("bytes helpers", func(t *testing.T) {
		got := evalInput(t, repl, `bytes_len("MZ")`)
		if got != "2" {
			t.Fatalf("bytes_len = %q, want %q", got, "2")
		}

		got = evalInput(t, repl, `bytes_get("MZ", 1)`)
		if got != "90" {
			t.Fatalf("bytes_get = %q, want %q", got, "90")
		}

		got = evalInput(t, repl, `bytes_slice("MZPE", 2, 2)`)
		if got != "PE" {
			t.Fatalf("bytes_slice = %q, want %q", got, "PE")
		}

		got = evalInput(t, repl, `bytes_read_u16_le("ABCD", 0)`)
		if got != "16961" {
			t.Fatalf("bytes_read_u16_le = %q, want %q", got, "16961")
		}

		got = evalInput(t, repl, `bytes_hex(255, 4)`)
		if got != "0x00FF" {
			t.Fatalf("bytes_hex = %q, want %q", got, "0x00FF")
		}

		got = evalInput(t, repl, `bytes_int_from_char("A")`)
		if got != "65" {
			t.Fatalf("bytes_int_from_char = %q, want %q", got, "65")
		}

		got = evalInput(t, repl, `bytes_write_u16_le("ABCD", 0, 16961)`)
		if got != "ABCD" {
			t.Fatalf("bytes_write_u16_le = %q, want %q", got, "ABCD")
		}

		got = evalInput(t, repl, `let c = bytes_cursor_new("AB"); bytes_cursor_tell(c)`)
		if got != "0" {
			t.Fatalf("bytes_cursor_tell = %q, want %q", got, "0")
		}

		got = evalInput(t, repl, `let c = bytes_cursor_new("AB"); bytes_cursor_read_u8(c)["value"]`)
		if got != "65" {
			t.Fatalf("bytes_cursor_read_u8 value = %q, want %q", got, "65")
		}

		got = evalInput(t, repl, `let c = bytes_cursor_new("AB"); bytes_cursor_read_u8(c)["cursor"]["offset"]`)
		if got != "1" {
			t.Fatalf("bytes_cursor_read_u8 next cursor offset = %q, want %q", got, "1")
		}
	})
}

func TestEvalCallErrors(t *testing.T) {
	repl := New()

	_, err := repl.Eval("unknown_fn(1)")
	if err == nil {
		t.Fatal("expected error for unknown function")
	}
	if !strings.Contains(err.Error(), "identifier not found: unknown_fn") {
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
		"float literals and numeric expressions",
		"arrays, hashes, indexing",
		"function literals and user-defined function calls",
		"struct/enum declarations, struct literals, and field access",
		"for loops with init/condition/post",
		"assignment expressions",
		"break and continue in loops",
		"function calls for browser-safe builtins",
		"builtins: len, first, last, rest, push, pop, putf, putln, bytes_* core (read/write + cursor), json_*, regex_*, text_* core set",
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

	expandedCandidates := repl.CompletionCandidates("policy_", "supported")
	joinedExpanded := strings.Join(expandedCandidates, "\n")
	if !strings.Contains(joinedExpanded, "policy_eval") {
		t.Fatalf("completion candidates missing expanded policy builtin: %v", expandedCandidates)
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

func TestEvalExpandedBrowserSafeBuiltins(t *testing.T) {
	repl := New()

	t.Run("policy eval and allow", func(t *testing.T) {
		input := `
policy_load("allow_policy", {
	"module": "package access
default allow = false
allow {
	true
}
decision = allow
rules = [1]",
  "eval_query": "data.access.decision",
  "allow_query": "data.access.allow",
  "rules_query": "data.access.rules"
});
policy_allow("allow_policy", {"user": "analyst"})
`
		got := evalInput(t, repl, input)
		if got != "true" {
			t.Fatalf("policy_allow output = %q, want %q", got, "true")
		}
	})

	t.Run("cache roundtrip", func(t *testing.T) {
		got := evalInput(t, repl, `cache_open("session"); cache_put("session", "k", 7); cache_get("session", "k")["value"]`)
		if got != "7.000000" {
			t.Fatalf("cache roundtrip output = %q, want %q", got, "7.000000")
		}
	})

	t.Run("db in-memory workflow", func(t *testing.T) {
		got := evalInput(t, repl, `let h = db_open(); let n1 = db_add_node(h); let n2 = db_add_node(h); db_add_edge(h, n1, n2); len(db_query_nodes(h))`)
		if got != "2" {
			t.Fatalf("db workflow output = %q, want %q", got, "2")
		}
	})
}
