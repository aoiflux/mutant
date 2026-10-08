package server

import (
	"strings"
	"testing"

	"mutant/lsp/internal/analyzer"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// format is formatSnapshotText for a source that is expected to parse, which
// is every case in this file but one. A refusal fails the test rather than
// returning "", so a test can never read the refusal as "formats to nothing".
func format(t *testing.T, src string) string {
	t.Helper()
	formatted, parseErrors, ok := formatSnapshotText(analyzer.New().Analyze(src))
	if !ok {
		t.Fatalf("the formatter refused %q: %v", src, parseErrors)
	}
	return formatted
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
		{"for", "for(let i=0;i<3;i=i+1){i;}", "for (let i = 0; i < 3; i = i + 1) {\n    i;\n}\n"},
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
		twice := format(t, once)
		if once != twice {
			t.Errorf("not idempotent for %q:\n first pass: %q\nsecond pass: %q", src, once, twice)
		}
	}
}

// TestFormatterRefusesSourceWithParseErrors is M26-TOOL-014's floor, at the
// level where the decision is made.
//
// This test used to be TestFormatterFallsBackOnParseErrors and asserted the
// defect: that `let = 5;   ` came back as `let = 5;`, trailing whitespace
// stripped. Stripping trailing whitespace with no tree to read is precisely
// what shortened the inside of a triple-quoted string, so the fallback is
// gone and the formatter refuses.
func TestFormatterRefusesSourceWithParseErrors(t *testing.T) {
	src := "let = 5;   \nlet ok = 1;   \n"

	formatted, parseErrors, ok := formatSnapshotText(analyzer.New().Analyze(src))
	if ok {
		t.Fatalf("the formatter accepted source that does not parse, giving %q", formatted)
	}
	if formatted != "" {
		t.Errorf("a refusal returned text: %q", formatted)
	}
	if len(parseErrors) == 0 {
		t.Fatal("a refusal must say why; got no parse errors")
	}
	for _, d := range parseErrors {
		if d.Severity == nil || *d.Severity != lsp.DiagnosticSeverityError {
			t.Errorf("parse diagnostic severity = %v, want error", d.Severity)
		}
		if d.Source == nil || *d.Source != "mutant-parser" {
			t.Errorf("parse diagnostic source = %v, want mutant-parser", d.Source)
		}
	}
}

func TestFormatterHandlesEmptyAndWhitespaceOnlyInput(t *testing.T) {
	for _, src := range []string{"", "   ", "\n\n\n", "\t\n  \n"} {
		if got := format(t, src); got != "" {
			t.Errorf("format(%q) = %q, want empty", src, got)
		}
	}
}

// TestFormatterKeepsTheBracketsTheAuthorWrote pins the owner's decision of
// 2026-09-29: the formatter keeps the brackets the author wrote and adds none.
// It used to bracket every operator expression, which buried a plain string
// concatenation under one pair per `+`.
func TestFormatterKeepsTheBracketsTheAuthorWrote(t *testing.T) {
	tests := []struct {
		src  string
		want string
	}{
		{"let x = a + b * c;", "let x = a + b * c;\n"},
		{"let x = (a + b) * c;", "let x = (a + b) * c;\n"},
		// A pair that precedence does not need is the author's, and stays.
		{"let x = a + (b * c);", "let x = a + (b * c);\n"},
		{"let ok = (flags & MASK) == 0;", "let ok = (flags & MASK) == 0;\n"},
		{"let ok = flags & MASK == 0;", "let ok = flags & MASK == 0;\n"},
		{"let x = a - (b - c);", "let x = a - (b - c);\n"},
		{"let x = a - b - c;", "let x = a - b - c;\n"},
		{"let x = -a;", "let x = -a;\n"},
		{"let x = !flag;", "let x = !flag;\n"},
		{"let x = -(a + b);", "let x = -(a + b);\n"},
		// Two minus signs stay apart: `--` is the decrement token.
		{"let x = - -a;", "let x = - -a;\n"},
		{"let x = -(-a);", "let x = -(-a);\n"},
		// Two pairs around one expression are one grouping.
		{"let x = ((a));", "let x = (a);\n"},
		{`putf("a=" + b + "\n");`, "putf(\"a=\" + b + \"\\n\");\n"},
		{`putf(("a=" + b));`, "putf((\"a=\" + b));\n"},
		{"let y = (-f)(1);", "let y = (-f)(1);\n"},
		{"let y = (a + b)[0];", "let y = (a + b)[0];\n"},
		{"x += (a + b) * c;", "x += (a + b) * c;\n"},
	}

	for _, tt := range tests {
		if got := format(t, tt.src); got != tt.want {
			t.Errorf("format(%q) = %q, want %q", tt.src, got, tt.want)
		}
	}
}

// TestFormatterBracketsWhatATreeWithoutTheSideTableNeeds covers the operand
// rules on their own. With the record of written brackets removed, the output
// must still parse back to the same tree, so every pair precedence needs is
// written -- and no other, which is why `(a - b) - (c - d)` loses one.
func TestFormatterBracketsWhatATreeWithoutTheSideTableNeeds(t *testing.T) {
	src := "let x = (a + b) * c;\n" +
		"let y = -(a + b);\n" +
		"let z = (a - b) - (c - d);\n" +
		"let w = a - (b - c);\n" +
		"let v = (-f)(1);\n" +
		"let u = (a + b)[0];\n" +
		"let t = (a || b) && !(c == d);\n" +
		"let s = - -a;\n"
	want := "let x = (a + b) * c;\n" +
		"let y = -(a + b);\n" +
		"let z = a - b - (c - d);\n" +
		"let w = a - (b - c);\n" +
		"let v = (-f)(1);\n" +
		"let u = (a + b)[0];\n" +
		"let t = (a || b) && !(c == d);\n" +
		"let s = - -a;\n"

	snapshot := analyzer.New().Analyze(src)
	if len(snapshot.ParseErrors) > 0 || snapshot.Program == nil {
		t.Fatalf("fixture did not parse: %v", snapshot.ParseErrors)
	}
	snapshot.Program.Parenthesized = nil
	got, _, ok := formatSnapshotText(snapshot)
	if !ok {
		t.Fatal("the fixture parses, so the formatter must not refuse it")
	}
	if got != want {
		t.Errorf("formatted without the side table =\n%s\nwant\n%s", got, want)
	}
}

// TestFormatterWritesTheBracketsAConditionNeeds is M26-LSP-008's regression
// test. The brackets around a condition belong to `if`, `while` and `match`,
// and the formatter used to leave them out whenever the printed condition began
// with '(' and ended with ')' -- which a call on a bracketed callee does too.
func TestFormatterWritesTheBracketsAConditionNeeds(t *testing.T) {
	tests := []struct {
		src  string
		want string // a line the output must contain
	}{
		{"let fs = [fn(x) { return x; }];\nlet more = [];\nif ((fs + more)[0](true)) { putln(1); }\n",
			"if ((fs + more)[0](true)) {"},
		{"let f = fn(x) { return x; };\nif ((-f)(1)) { putln(1); }\n", "if ((-f)(1)) {"},
		{"let h = {\"a\": 1};\nmatch ((h)[\"a\"]) { 1 => putln(1), _ => putln(2) }\n", "match ((h)[\"a\"]) {"},
		{"let a = 1;\nif (a + a > 1) { putln(1); }\n", "if (a + a > 1) {"},
		{"let i = 0;\nwhile (i < 3) { i = i + 1; }\n", "while (i < 3) {"},
	}

	for _, tt := range tests {
		got := format(t, tt.src)
		if !strings.Contains(got, tt.want) {
			t.Errorf("format(%q) = %q, want it to contain %q", tt.src, got, tt.want)
		}
		reparsed := analyzer.New().Analyze(got)
		if len(reparsed.ParseErrors) > 0 || reparsed.Program == nil {
			t.Errorf("format(%q) = %q, which does not parse: %v", tt.src, got, reparsed.ParseErrors)
			continue
		}
		before := canonicalRendering(analyzer.New().Analyze(tt.src).Program.String())
		if after := canonicalRendering(reparsed.Program.String()); after != before {
			t.Errorf("format(%q) changed the tree\n%s", tt.src, firstDifference(before, after))
		}
		again, _, ok := formatSnapshotText(reparsed)
		if !ok {
			t.Errorf("format(%q) = %q, which the formatter then refused", tt.src, got)
			continue
		}
		if again != got {
			t.Errorf("formatting %q twice gave %q, then %q", tt.src, got, again)
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

// TestFormatterKeepsWhitespaceInsideStringsOfAFileThatParses is the control
// for M26-TOOL-014: the same banner, in a file with nothing wrong with it,
// keeps its three trailing spaces. The defect was never in the printer -- it
// was in what used to happen when the printer could not run at all.
func TestFormatterKeepsWhitespaceInsideStringsOfAFileThatParses(t *testing.T) {
	src := "let banner = \"\"\"\nrow one   \nrow two\n\"\"\";\n"

	got := format(t, src)
	if !strings.Contains(got, "row one   ") {
		t.Errorf("the formatter edited the inside of a string literal:\n%q", got)
	}
}
