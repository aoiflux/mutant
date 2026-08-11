package server

import (
	"strings"
	"testing"

	"mutant/lsp/internal/analyzer"
)

func format(t *testing.T, src string) string {
	t.Helper()
	return formatSnapshotText(analyzer.New().Analyze(src))
}

func TestFormatterUsesFourSpaceIndent(t *testing.T) {
	got := format(t, "let answer=fn(x){if (x > 0) {return x;} else {return 0;}};")
	want := "let answer = fn(x) {\n" +
		"    if (x > 0) {\n" +
		"        return x;\n" +
		"    } else {\n" +
		"        return 0;\n" +
		"    }\n" +
		"};\n"

	if got != want {
		t.Fatalf("formatted = %q\nwant       %q", got, want)
	}
	if strings.Contains(got, "\t") {
		t.Error("formatted output contains a tab; Mutant indents with spaces only")
	}
}

func TestFormatterInsertsMissingSemicolons(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{"let", "let x = 5", "let x = 5;\n"},
		{"expression", "answer", "answer;\n"},
		{"return", "let f = fn() { return 5 }", "let f = fn() {\n    return 5;\n};\n"},
		{"break", "for (;;) { break }", "for (; ; ) {\n    break;\n}\n"},
		{"multiple", "let x = 1\nlet y = 2", "let x = 1;\nlet y = 2;\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := format(t, tt.src); got != tt.want {
				t.Errorf("formatted = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatterRemovesRedundantSemicolons(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{"double", "let x = 5;;", "let x = 5;\n"},
		{"triple", "let x = 5;;;", "let x = 5;\n"},
		{"inside block", "let f = fn() { let x = 1;; };", "let f = fn() {\n    let x = 1;\n};\n"},
		{"leading", ";let x = 5;", "let x = 5;\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := format(t, tt.src); got != tt.want {
				t.Errorf("formatted = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatterOmitsSemicolonAfterBraceTerminatedStatements(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{"if", "if (x) { y; }", "if (x) {\n    y;\n}\n"},
		{"if else", "if (x) { y; } else { z; }", "if (x) {\n    y;\n} else {\n    z;\n}\n"},
		{"struct", "struct Point{x;y;}", "struct Point { x; y; }\n"},
		{"enum", "enum Color{Red,Green}", "enum Color { Red, Green }\n"},
		{"for", "for(let i=0;i<3;i=i+1){i;}", "for (let i = 0; (i < 3); i = (i + 1)) {\n    i;\n}\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := format(t, tt.src); got != tt.want {
				t.Errorf("formatted = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatterPreservesComments(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			"leading and trailing",
			"// header\nlet   answer=1; // inline\n",
			"// header\nlet answer = 1; // inline\n",
		},
		{
			"comment inside block",
			"let f=fn(){\n// note\nlet x=1;\n};",
			"let f = fn() {\n    // note\n    let x = 1;\n};\n",
		},
		{
			"comment after last statement in block",
			"let f=fn(){\nlet x=1;\n// tail\n};",
			"let f = fn() {\n    let x = 1;\n    // tail\n};\n",
		},
		{
			"comment only block",
			"let f=fn(){\n// just this\n};",
			"let f = fn() {\n    // just this\n};\n",
		},
		{
			"trailing comment at end of file",
			"let x = 1;\n// last word\n",
			"let x = 1;\n// last word\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := format(t, tt.src); got != tt.want {
				t.Errorf("formatted = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatterCollapsesBlankLineRuns(t *testing.T) {
	src := "let a = 1;\n\n\n\nlet b = 2;\n"
	want := "let a = 1;\n\nlet b = 2;\n"

	if got := format(t, src); got != want {
		t.Errorf("formatted = %q, want %q", got, want)
	}
}

func TestFormatterDoesNotInventBlankLines(t *testing.T) {
	src := "let f = fn() {\n    let x = 1;\n    let y = 2;\n};\n"

	if got := format(t, src); got != src {
		t.Errorf("formatted = %q, want unchanged %q", got, src)
	}
}

// HashLiteral.Pairs is a Go map. Printing it without sorting yields a
// different byte sequence per run, which would make formatting
// non-deterministic and break format-on-save.
func TestFormatterIsDeterministicForHashLiterals(t *testing.T) {
	src := `let h = {"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6};`

	first := format(t, src)
	for i := 0; i < 50; i++ {
		if got := format(t, src); got != first {
			t.Fatalf("run %d produced %q, first run produced %q", i, got, first)
		}
	}
}

// Indexing and calls must hug their brackets: `parsed["events"]`, never
// `parsed ["events"]`. The old text-based formatter inserted a space here,
// so this is a regression guard as much as a specification.
func TestFormatterDoesNotSpaceBeforeBrackets(t *testing.T) {
	tests := []struct {
		src  string
		want string
	}{
		{"let events = parsed[\"events\"];", "let events = parsed[\"events\"];\n"},
		{"let events = parsed [\"events\"];", "let events = parsed[\"events\"];\n"},
		{"let ev = events [i];", "let ev = events[i];\n"},
		{"let v = a [b] [c];", "let v = a[b][c];\n"},
		{"let v = obj.field [0];", "let v = obj.field[0];\n"},
		{"f (1, 2);", "f(1, 2);\n"},
		{"let v = f (x) [0];", "let v = f(x)[0];\n"},
		// An array literal in value position keeps its space after `=`.
		{"let findings = [];", "let findings = [];\n"},
		{"let nums = [1, 2, 3];", "let nums = [1, 2, 3];\n"},
	}

	for _, tt := range tests {
		got := format(t, tt.src)
		if got != tt.want {
			t.Errorf("format(%q) = %q, want %q", tt.src, got, tt.want)
		}
	}
}

func TestFormatterPreservesHashKeyOrder(t *testing.T) {
	src := `let h = {"zebra": 1, "apple": 2, "mango": 3};`
	want := "let h = {\"zebra\": 1, \"apple\": 2, \"mango\": 3};\n"

	// Authored order, not alphabetical — and stable across runs.
	for i := 0; i < 25; i++ {
		if got := format(t, src); got != want {
			t.Fatalf("run %d: formatted = %q, want %q", i, got, want)
		}
	}
}

func TestFormatterIsIdempotent(t *testing.T) {
	corpus := []string{
		"let x = 5",
		"let x = 5;;",
		"let answer=fn(x){if (x > 0) {return x;} else {return 0;}};",
		"// header\nlet   answer=1; // inline\n",
		"let a = 1;\n\n\n\nlet b = 2;\n",
		"struct Point{x;y;}",
		"enum Color{Red,Green}",
		"for(let i=0;i<3;i=i+1){i;}",
		`let h = {"a": 1, "b": 2};`,
		"let arr=[1,2,3];\nlet first=arr[0];",
		"let msg=\"hello world\";\nmsg;",
		"let f=fn(){\n// note\nlet x=1;\n\n// second\nlet y=2;\n};",
		"let p = Point { x: 1, y: 2 };",
		"let neg = -5;\nlet not = !true;",
		"for (;;) { break; }",
		"let f = fn(a, b) { return a, b; };",
		"obj.field.nested;",
		"let m = macro(x) { x; };",
	}

	for _, src := range corpus {
		once := format(t, src)
		twice := formatSnapshotText(analyzer.New().Analyze(once))
		if once != twice {
			t.Errorf("not idempotent for %q:\n first pass: %q\nsecond pass: %q", src, once, twice)
		}
	}
}

func TestFormatterFallsBackOnParseErrors(t *testing.T) {
	// `let = 5` cannot produce a usable tree, so the formatter must not
	// attempt to print one; it only normalises whitespace.
	src := "let = 5;   \nlet ok = 1;   \n"
	want := "let = 5;\nlet ok = 1;\n"

	if got := format(t, src); got != want {
		t.Errorf("formatted = %q, want %q", got, want)
	}
}

func TestFormatterHandlesEmptyAndWhitespaceOnlyInput(t *testing.T) {
	for _, src := range []string{"", "   ", "\n\n\n", "\t\n  \n"} {
		if got := format(t, src); got != "" {
			t.Errorf("format(%q) = %q, want empty", src, got)
		}
	}
}

func TestFormatterParenthesizesOperatorExpressions(t *testing.T) {
	tests := []struct {
		src  string
		want string
	}{
		{"let x = a + b * c;", "let x = (a + (b * c));\n"},
		{"let x = (a + b) * c;", "let x = ((a + b) * c);\n"},
		{"let x = -a;", "let x = (-a);\n"},
		{"let x = !flag;", "let x = (!flag);\n"},
		// Redundant grouping parens are dropped by the parser, so the
		// canonical form has exactly one pair per operator.
		{"let x = ((a));", "let x = a;\n"},
	}

	for _, tt := range tests {
		if got := format(t, tt.src); got != tt.want {
			t.Errorf("format(%q) = %q, want %q", tt.src, got, tt.want)
		}
	}
}

func TestFormatterNormalizesTabsAndTrailingWhitespace(t *testing.T) {
	src := "let\tx\t=\t5;   \n\tlet y = 6;  \n"
	want := "let x = 5;\nlet y = 6;\n"

	got := format(t, src)
	if got != want {
		t.Errorf("formatted = %q, want %q", got, want)
	}
	for _, line := range strings.Split(got, "\n") {
		if strings.TrimRight(line, " \t") != line {
			t.Errorf("line %q has trailing whitespace", line)
		}
	}
}
