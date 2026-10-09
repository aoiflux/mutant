package parser

import (
	"strings"
	"testing"
	"time"

	"mutant/lexer"
)

// parse is the shorthand the tests below share: source in, the parser out,
// with its program already built.
func parse(t *testing.T, src string) (*Parser, string) {
	t.Helper()
	p := New(lexer.New(src))
	program := p.ParseProgram()
	var rendered string
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Program.String() panicked on %q: %v", trim(src), r)
			}
		}()
		rendered = program.String()
	}()
	return p, rendered
}

func trim(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

func hasError(p *Parser, substr string) bool {
	for _, e := range p.Errors() {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- M26-LEX-008

// TestALeadingZeroIsRefusedRatherThanReadAsOctal covers the literal half of the
// leading-zero defect. `010` was 8 and `0100 + 1` was 65, with nothing said,
// because the literal was parsed with strconv base 0.
//
// It is refused rather than read as decimal because the text does not say which
// was meant: a zero-padded field pasted out of a date or an offset listing
// means ten, and `0755` written by hand means a permission mask.
func TestALeadingZeroIsRefusedRatherThanReadAsOctal(t *testing.T) {
	for _, src := range []string{"010;", "0100 + 1;", "08;", "0755;", "00;",
		"let month = 09;", "match (x) { 010 => 1, _ => 2 };"} {
		p, _ := parse(t, src)
		if !hasError(p, "a leading zero does not make") {
			t.Errorf("%q: no leading-zero refusal, errors=%v", src, p.Errors())
		}
	}

	// The refusal says what to write instead, in both readings, because either
	// may be the one that was meant.
	p, _ := parse(t, "0755;")
	if !hasError(p, "write 755 for the decimal value") || !hasError(p, `parse_int("0755", 8)`) {
		t.Errorf("the refusal should name both readings, got %v", p.Errors())
	}

	// A single zero is a number, not a prefix, and ordinary decimals are
	// untouched. A float never had the second reading -- no language reads
	// 010.5 as octal -- so it keeps parsing.
	for _, src := range []string{"0;", "10;", "1000;", "010.5;", "0.5;"} {
		p, _ := parse(t, src)
		if len(p.Errors()) != 0 {
			t.Errorf("%q should parse, got %v", src, p.Errors())
		}
	}
}

// TestBaseZeroNeverReachedAnythingButTheLeadingZero records why base 10 costs
// no capability: the lexer's readNumber loops on IsDigit and '.', so a prefix
// is split off as a separate identifier and never reaches
// parseIntegerLiteral in one token. The leading zero was the only thing base 0
// was ever handed here.
//
// This asserts the token stream rather than a parse error, because whether the
// split is an error depends on where it sits: in an argument list the trailing
// identifier is a hard error, while as a bare statement it is two statements
// with a recoverable missing semicolon between them. The split is the part that
// makes the base irrelevant.
func TestBaseZeroNeverReachedAnythingButTheLeadingZero(t *testing.T) {
	for _, tc := range []struct {
		src   string
		first string
		then  string
	}{
		{"0x1F;", "0", "x1F"},
		{"0b101;", "0", "b101"},
		{"0o17;", "0", "o17"},
		{"1_000;", "1", "_000"},
	} {
		l := lexer.New(tc.src)
		one, two := l.NextToken(), l.NextToken()
		if string(one.Type) != "INT" || one.Literal != tc.first {
			t.Errorf("%q: first token %s(%s), want INT(%s)", tc.src, one.Type, one.Literal, tc.first)
		}
		if string(two.Type) != "IDENT" || two.Literal != tc.then {
			t.Errorf("%q: second token %s(%s), want IDENT(%s)", tc.src, two.Type, two.Literal, tc.then)
		}
	}

	// The leading zero, by contrast, is one INT token, which is how it reached
	// strconv with base 0 and came back as octal.
	l := lexer.New("010;")
	if one := l.NextToken(); string(one.Type) != "INT" || one.Literal != "010" {
		t.Errorf("010 lexed as %s(%s), want INT(010)", one.Type, one.Literal)
	}
}

// ---------------------------------------------------------------- M26-LEX-005

// TestAnUnterminatedLiteralIsRefusedInEverySpelling covers the row's own
// reproduction. `let note = "unterminated;` compiled, the program ran the
// statements before it and reported success, and the ledger verification and
// exit(3) after it never ran -- they were inside the string.
func TestAnUnterminatedLiteralIsRefusedInEverySpelling(t *testing.T) {
	for _, src := range []string{`let s = "abc`, `let s = r"abc`,
		`let s = """abc`, `let s = r"""abc`} {
		p, _ := parse(t, src)
		if !hasError(p, "unterminated string literal") {
			t.Errorf("%q: not refused, errors=%v", src, p.Errors())
		}
		if !hasError(p, "line 1, column 9") {
			t.Errorf("%q: should name where the literal opens, got %v", src, p.Errors())
		}
	}

	// The row's program, whole: the swallowed text is what the refusal exists
	// to stop being swallowed.
	src := "putln(\"one\");\nlet note = \"unterminated;\nputln(ledger_verify_everything());\nexit(3);"
	p, _ := parse(t, src)
	if !hasError(p, "unterminated string literal") {
		t.Fatalf("the row's program should be refused, errors=%v", p.Errors())
	}

	// A literal that IS closed, in every spelling, still parses -- including a
	// quote spanning lines, which has always been legal, and a hole, which must
	// not be split out of a literal that was never closed.
	for _, src := range []string{`let s = "abc";`, `let s = r"abc";`,
		`let s = """abc""";`, `let s = r"""abc""";`, "let s = \"a\nb\";",
		`let s = "${ 1 + 1 }";`} {
		p, _ := parse(t, src)
		if len(p.Errors()) != 0 {
			t.Errorf("%q should parse, got %v", src, p.Errors())
		}
	}
}

// TestAnUnclosedBlockIsRefused is the verifier's addition to the same row, and
// it is the same mistake in the same direction: end of input treated as a
// terminator. `let f = fn() { return 1;` followed by `putln(f());` put the call
// inside f's body, so it never ran, and the parse reported nothing at all.
func TestAnUnclosedBlockIsRefused(t *testing.T) {
	for _, src := range []string{
		"let f = fn() { return 1;\nputln(f());",
		"if (true) { putln(1);",
		"for (let i = 0; i < 2; i = i + 1) { putln(i);",
		"while (true) { putln(1);",
	} {
		p, _ := parse(t, src)
		if !hasError(p, "unclosed block") {
			t.Errorf("%q: not refused, errors=%v", src, p.Errors())
		}
	}

	for _, src := range []string{
		"let f = fn() { return 1; };\nputln(f());",
		"if (true) { putln(1); }",
		"while (false) { putln(1); }",
	} {
		p, _ := parse(t, src)
		if len(p.Errors()) != 0 {
			t.Errorf("%q should parse, got %v", src, p.Errors())
		}
	}
}

// ---------------------------------------------------------------- M26-LEX-003

// TestDeepNestingIsRefusedRatherThanOverflowingTheStack is written to fail
// loudly: a stack overflow is fatal, recover() cannot catch it, and it takes
// the whole test binary with it. So if the bound regresses, this test does not
// report a failure -- the run dies, which is louder.
//
// 200,000 levels is the row's figure. At HEAD 100,000 parsed in 85 ms and
// 1,000,000 ended the process.
func TestDeepNestingIsRefusedRatherThanOverflowingTheStack(t *testing.T) {
	cases := map[string]string{
		"nested parens":    strings.Repeat("(", 200000),
		"prefix operators": strings.Repeat("!", 200000) + "x",
		"array literals":   strings.Repeat("[", 200000),
		"nested blocks":    strings.Repeat("if (true) {", 50000),
	}

	for name, src := range cases {
		start := time.Now()
		p, _ := parse(t, src)
		if elapsed := time.Since(start); elapsed > 30*time.Second {
			t.Errorf("%s: took %s", name, elapsed)
		}
		if !hasError(p, "nested more than") {
			t.Errorf("%s: no nesting refusal, first errors=%v", name, first(p.Errors(), 3))
		}
	}
}

// TestTheNestingBoundLeavesOrdinaryNestingAlone keeps the bound from being the
// defect. Nothing written by hand nests near it, and a left-associative chain
// does not nest at all: the loop in parseExpression consumes `1+1+1+...`
// without the stack growing, which is why a long expression is not a deep one.
func TestTheNestingBoundLeavesOrdinaryNestingAlone(t *testing.T) {
	for name, src := range map[string]string{
		"a hundred parens":         strings.Repeat("(", 100) + "1" + strings.Repeat(")", 100) + ";",
		"a long additive chain":    "1" + strings.Repeat(" + 1", 5000) + ";",
		"ten nested if bodies":     strings.Repeat("if (true) {", 10) + "1;" + strings.Repeat("}", 10),
		"nested data literals":     strings.Repeat("[", 50) + "1" + strings.Repeat("]", 50) + ";",
		"nested function literals": strings.Repeat("fn() {", 20) + "1;" + strings.Repeat("};", 20),
	} {
		p, _ := parse(t, src)
		if len(p.Errors()) != 0 {
			t.Errorf("%s should parse, got %v", name, first(p.Errors(), 3))
		}
	}
}

// TestTheErrorListIsCapped covers the other half of the row: one error per
// unclosed paren meant 700,001 of them for a 700 KB file of nothing else.
func TestTheErrorListIsCapped(t *testing.T) {
	p, _ := parse(t, strings.Repeat("(", 200000))
	if len(p.Errors()) > maxParseErrors+1 {
		t.Errorf("errors = %d, want at most %d plus the note", len(p.Errors()), maxParseErrors)
	}
	if !hasError(p, "too many parse errors") {
		t.Errorf("a capped list should say it was capped, got %d errors", len(p.Errors()))
	}
	// The cap is on the list, not on the parse: the first errors are kept, and
	// they are the ones that say what is wrong.
	if !hasError(p, "nested more than") {
		t.Errorf("the first error should survive the cap, got %v", first(p.Errors(), 3))
	}
}

// ---------------------------------------------------------------- M26-LEX-010

// TestStringNeverPanicsOnTheTreesAParseReturns drives the half of the invariant
// that needs real parser output. Every input here is a tree with holes in it:
// parseExpression appends an error and returns nil, and the node that asked for
// the operand keeps that nil as a child.
//
// The language server died on the fourth of these -- the whole process, rc=2 --
// because it calls String() on an assignment's target to lint it, and nothing
// between that call and the jsonrpc2 reader goroutine recovers.
func TestStringNeverPanicsOnTheTreesAParseReturns(t *testing.T) {
	for _, src := range []string{
		"1 + ;", "-;", "!", "f()[-,] = 1;", "[1][1 + ,] = 3;",
		"a[-] = v;", "a[-][0] = 1;", "a[i + ][0] = 3;",
		"let x = ;", "return ;", "if () { }", "while () { }",
		"for (;;) {", "fn(", "f(1, , 2);", "{1: };", "[1, , 2];",
		"x.;", "match (x) { => 1 };", "let s = \"abc", "010;",
		"struct S { };", "enum E { };", "x = ;", "x += ;",
		`"${ }"`, `"${ 1 + }"`, "import ;",
	} {
		// parse() is the assertion: it calls Program.String() inside a recover
		// and fails the test on a panic. Nothing is checked about the text
		// here, because for several of these the honest rendering is the empty
		// string -- the statement was dropped, not left with a hole.
		parse(t, src)
	}
}

// TestAMissingChildIsNamedInTheRendering is the measurable half: the tree that
// killed the server renders, and says where the hole is.
func TestAMissingChildIsNamedInTheRendering(t *testing.T) {
	_, rendered := parse(t, "f()[-,] = 1;")
	if !strings.Contains(rendered, "<missing>") {
		t.Fatalf("a tree with a hole should name it, got %q", rendered)
	}
}

func first(errs []string, n int) []string {
	if len(errs) < n {
		return errs
	}
	return errs[:n]
}
