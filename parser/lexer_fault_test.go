package parser

import (
	"strings"
	"testing"

	"mutant/ast"
	"mutant/lexer"
)

// What the lexer refuses has to reach the author, and it reaches them through
// the parser. These tests are the other half of lexer/termination_test.go: that
// an ILLEGAL token is a positioned parse error, and that the message is the
// lexer's sentence rather than the parser's guess at one.
//
// Every test here fails at a812eee except TestWellFormedParameterListsStillParse,
// which is the guard that the fix refuses only what it means to refuse. The
// sources the first four tests use parse with zero errors at a812eee; the two
// parameter-slot tests are the ones the 2026-10-07 review added, and at a812eee
// their sources produce either zero errors or two generic ones, never the one
// positioned error they assert.

// faults parses src and returns its plain and typed errors.
func faults(src string) ([]string, []ParseError) {
	p := New(lexer.New(src))
	p.ParseProgram()
	return p.Errors(), p.TypedErrors()
}

// oneFault is the single typed error src produces, and fails if there is not
// exactly one. A lexical fault should cost one diagnostic: the editor shows the
// first, and a cascade hides it.
func oneFault(t *testing.T, src string) ParseError {
	t.Helper()
	plain, typed := faults(src)
	if len(typed) != 1 {
		t.Fatalf("%q produced %d typed errors, want 1: %v", src, len(typed), plain)
	}
	return typed[0]
}

// M26-LEX-005's regression test as the row asks for it: each of "abc, r"abc,
// """abc and r"""abc yields a positioned error.
func TestAnUnterminatedLiteralIsAPositionedParseError(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"ordinary", "let a = \"abc\nlet b = 1;\nputln(b);\n"},
		{"raw", "let a = r\"abc\nlet b = 1;\n"},
		{"triple", "let a = \"\"\"abc\nlet b = 1;\n"},
		{"raw triple", "let a = r\"\"\"abc\nlet b = 1;\n"},
		{"bare", `"abc`},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := oneFault(t, tt.src)
			if !strings.Contains(err.Msg, "unterminated") {
				t.Errorf("message = %q, want it to say the literal is unterminated", err.Msg)
			}
			if err.Range.Start.Line != 1 {
				t.Errorf("the error starts on line %d, want 1", err.Range.Start.Line)
			}
			wantCol := 9
			if tt.name == "bare" {
				wantCol = 1
			}
			if err.Range.Start.Column != wantCol {
				t.Errorf("the error starts at column %d, want %d (the literal's first character)",
					err.Range.Start.Column, wantCol)
			}
		})
	}
}

// M26-LEX-006: everything after the NUL used to be dropped, so this program
// parsed as `let a = 1;` alone and compiled.
func TestANULByteIsAPositionedParseError(t *testing.T) {
	src := "let a = 1;" + string(rune(0)) + "let b = 2;\nputln(b);\n"
	err := oneFault(t, src)

	if !strings.Contains(err.Msg, "NUL") {
		t.Errorf("message = %q, want it to name the NUL byte", err.Msg)
	}
	if err.Range.Start.Line != 1 || err.Range.Start.Column != 11 {
		t.Errorf("the error is at %d:%d, want 1:11 (the byte itself)",
			err.Range.Start.Line, err.Range.Start.Column)
	}
}

// M26-LEX-017: the hole was closed at the end of the literal, so this set a to
// "v=3" and reported nothing. scanHole's own comment claimed "the resulting
// error points inside the string", and there was no error to point anywhere.
func TestAnUnterminatedHoleIsAPositionedParseError(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"triple", "let a = \"\"\"v=${1+2\"\"\";\nputln(a);\n"},
		{"ordinary", "let a = \"v=${1+2\";\n"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := oneFault(t, tt.src)
			if !strings.Contains(err.Msg, "unterminated ${") {
				t.Errorf("message = %q, want it to name the unterminated ${", err.Msg)
			}
			if err.Range.Start.Line != 1 || err.Range.Start.Column != 9 {
				t.Errorf("the error is at %d:%d, want 1:9 (the literal)",
					err.Range.Start.Line, err.Range.Start.Column)
			}
		})
	}
}

// The lexer's account replaces the parser's, and only where the lexer has one.
// A character the lexer has nothing to say about still gets the parser's own
// message, so this pins illegalDetail in both directions rather than only in
// the direction the fix needed.
func TestTheLexersAccountReplacesTheParsersGuess(t *testing.T) {
	err := oneFault(t, `let a = "abc`)
	if strings.Contains(err.Msg, "no prefix parse function") {
		t.Errorf("message = %q, want the lexer's sentence instead of the parser's", err.Msg)
	}

	// `@` is ILLEGAL and carries no account: nothing is wrong with the file
	// beyond there being no rule that starts with it, which is exactly what
	// the parser's own message says.
	plain, typed := faults(`let a = @;`)
	if len(typed) == 0 {
		t.Fatalf("`let a = @;` produced no error at all")
	}
	if !strings.Contains(typed[0].Msg, "no prefix parse function") {
		t.Errorf("message for `@` = %q, want the parser's own message: %v", typed[0].Msg, plain)
	}
}

// A parameter slot was the one position in the grammar where an ILLEGAL never
// became an error. parseFunctionParameters took p.curToken.Literal as a
// parameter's name without asking what the token was, so once the lexer started
// producing a one-token ILLEGAL for a NUL-bearing literal, these parsed with no
// diagnostic anywhere: the illegal text became the parameter's name, and both of
// the caller's expectPeeks then found the `)` and the `{` they wanted. Worse than
// silent -- with no ParseError the AST printer runs, so `mutant fmt` rewrote the
// first of these from 25 bytes to 30, raw NUL and all, where a812eee without the
// lexer half of this kit left it alone. Each source here now costs exactly one
// error and it is the lexer's own sentence.
func TestAnIllegalTokenInAParameterSlotIsRefused(t *testing.T) {
	nul := string(rune(0))
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"fn, only parameter", "let f = fn(\"a" + nul + "b\") { 1 };\n", "NUL"},
		{"fn, second parameter", "let f = fn(x, \"a" + nul + "b\") { 1 };\n", "NUL"},
		{"fn, first of two", "let f = fn(\"a" + nul + "b\", x) { 1 };\n", "NUL"},
		{"macro", "let m = macro(\"a" + nul + "b\") { quote(1) };\n", "NUL"},
		{"bare NUL", "let f = fn(" + nul + ") { 1 };\n", "NUL"},
		{"NUL in a comment", "let f = fn(// hi" + nul + "\nx) { 1 };\n", "NUL"},
		{"unterminated hole", "let f = fn(\"\"\"v=${1+2\"\"\") { 1 };\n", "unterminated ${"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := oneFault(t, tt.src)
			if !strings.Contains(err.Msg, tt.want) {
				t.Errorf("message = %q, want it to name %s", err.Msg, tt.want)
			}
			if err.Range.Start.Line != 1 {
				t.Errorf("the error starts on line %d, want 1", err.Range.Start.Line)
			}
		})
	}
}

// A parameter is a name and nothing else. This half is a defect that predates
// the three rows this kit is about and is closed by the same guard, so it is
// pinned here rather than left for the reader to rediscover: at a812eee `fn(1)`
// declared a parameter called 1 and `fn("ok")` one called ok, with no diagnostic
// at all, and `mutant fmt` then rewrote the second from 24 bytes to 27 as
// `fn(ok)` -- the author's quotes gone from the author's file.
func TestAParameterMustBeAName(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"integer", "let f = fn(1) { 1 };\n"},
		{"string", "let f = fn(\"ok\") { 1 };\n"},
		{"string, second of two", "let f = fn(x, \"ok\") { 1 };\n"},
		{"macro, integer", "let m = macro(1) { quote(1) };\n"},
		{"illegal character", "let f = fn(@) { 1 };\n"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := oneFault(t, tt.src)
			if !strings.Contains(err.Msg, "must be a name") {
				t.Errorf("message = %q, want it to say a parameter must be a name", err.Msg)
			}
			if err.Range.Start.Line != 1 {
				t.Errorf("the error starts on line %d, want 1", err.Range.Start.Line)
			}
		})
	}
}

// The guard refuses only what it means to refuse. This one passes at a812eee as
// well, which is its job.
func TestWellFormedParameterListsStillParse(t *testing.T) {
	cases := []struct {
		src  string
		want []string
	}{
		{"let f = fn() { 1 };\n", nil},
		{"let f = fn(x) { x };\n", []string{"x"}},
		{"let f = fn(x, y) { x + y };\n", []string{"x", "y"}},
		{"let f = fn(a, b, c) { a };\n", []string{"a", "b", "c"}},
		{"let m = macro(x) { quote(unquote(x)) };\n", []string{"x"}},
	}

	for _, tt := range cases {
		t.Run(tt.src, func(t *testing.T) {
			p := New(lexer.New(tt.src))
			prog := p.ParseProgram()
			if len(p.Errors()) != 0 {
				t.Fatalf("%q produced errors: %v", tt.src, p.Errors())
			}
			got := parameterNamesOf(t, prog)
			if len(got) != len(tt.want) {
				t.Fatalf("parameters = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parameter %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// parameterNamesOf is the parameter list of the single fn or macro literal the
// program's one let statement binds.
func parameterNamesOf(t *testing.T, prog *ast.Program) []string {
	t.Helper()
	if len(prog.Statements) != 1 {
		t.Fatalf("program has %d statements, want 1", len(prog.Statements))
	}
	let, ok := prog.Statements[0].(*ast.LetStatement)
	if !ok {
		t.Fatalf("statement is %T, want *ast.LetStatement", prog.Statements[0])
	}
	var params []*ast.Identifier
	switch v := let.Value.(type) {
	case *ast.FunctionLiteral:
		params = v.Parameters
	case *ast.MacroLiteral:
		params = v.Parameters
	default:
		t.Fatalf("bound value is %T, want a fn or a macro literal", let.Value)
	}
	names := make([]string, 0, len(params))
	for _, param := range params {
		names = append(names, param.Value)
	}
	return names
}
