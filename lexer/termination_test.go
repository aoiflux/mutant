package lexer

import (
	"strings"
	"testing"

	"mutant/token"
)

// The three rows pinned here are one defect in three costumes: the lexer
// decided a program had ended, and said nothing about it. M26-LEX-005 ended it
// at a quote that is never closed, M26-LEX-006 at a NUL byte, M26-LEX-017 at a
// ${ with no }. Every test in this file fails at a812eee, where each of those
// inputs lexes clean and compiles into a program the author did not write.

// allTokens reads the whole stream, bounded so a regression reports instead of
// hanging the suite -- a lexer is never asked whether it is finished, so an
// unbounded drain is how the last stall took down the whole test run.
func allTokens(t *testing.T, src string) []token.Token {
	t.Helper()
	l := New(src)
	out := []token.Token{}
	for i := 0; i <= len(src)+16; i++ {
		tok := l.NextToken()
		out = append(out, tok)
		if tok.Type == token.EOF {
			return out
		}
	}
	t.Fatalf("the lexer never reached EOF on %q", src)
	return nil
}

// types is the token stream as a readable string, for a one-line failure.
func types(toks []token.Token) string {
	out := make([]string, 0, len(toks))
	for _, tok := range toks {
		out = append(out, string(tok.Type))
	}
	return strings.Join(out, " ")
}

// onlyIllegal is the single ILLEGAL token in the stream, and fails if there is
// not exactly one. One fault has to cost one token: a lexer that reports the
// same mistake per character buries the first message.
func onlyIllegal(t *testing.T, src string) token.Token {
	t.Helper()
	toks := allTokens(t, src)
	var hit []token.Token
	for _, tok := range toks {
		if tok.Type == token.ILLEGAL {
			hit = append(hit, tok)
		}
	}
	if len(hit) != 1 {
		t.Fatalf("%q produced %d ILLEGAL tokens, want 1: %s", src, len(hit), types(toks))
	}
	return hit[0]
}

// onlyUnterminated is onlyIllegal for the literal that never closed, which this
// tree reports as a token type of its own rather than as an ILLEGAL carrying a
// message. See the comment on TestAnUnterminatedLiteralIsRefusedAndSaysWhere.
func onlyUnterminated(t *testing.T, src string) token.Token {
	t.Helper()
	toks := allTokens(t, src)
	var hit []token.Token
	for _, tk := range toks {
		if tk.Type == token.UNTERMINATED {
			hit = append(hit, tk)
		}
	}
	if len(hit) != 1 {
		t.Fatalf("%q produced %d UNTERMINATED tokens, want 1: %s", src, len(hit), types(toks))
	}
	return hit[0]
}

// M26-LEX-005. Each of these used to lex as a STRING whose value was the rest
// of the file, with no diagnostic anywhere: `let a = "abc` followed by two more
// statements compiled, and `mutant fmt` then wrote those statements back into
// the literal as \n escapes.
//
// The row is closed, and not by this kit: it landed in e836bea as
// token.UNTERMINATED, a token type of its own with its own parser prefix
// handler. This kit was designed before that and reports the same thing as an
// ILLEGAL carrying Err, which is the right shape for the other two rows here --
// one character inside a construct that was otherwise read -- and the wrong one
// for this, a token many runes wide that was read correctly and that no program
// can contain. The eleven spellings are what this test is worth keeping for;
// they are wider than the four the landed fix pinned, and they are checked here
// at the lexer rather than through the parser. The assertion is the landed
// token type.
func TestAnUnterminatedLiteralIsRefusedAndSaysWhere(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		openAt   int // byte offset of the literal's first character
		openLine int
		openCol  int
	}{
		{"ordinary", `"abc`, 0, 1, 1},
		{"raw", `r"abc`, 0, 1, 1},
		{"triple", `"""abc`, 0, 1, 1},
		{"raw triple", `r"""abc`, 0, 1, 1},
		{"trailing backslash", `"abc\`, 0, 1, 1},
		{"one quote", `"`, 0, 1, 1},
		{"three quotes", `"""`, 0, 1, 1},
		{"ordinary eats two statements", "let a = \"abc\nlet b = 1;\nputln(b);\n", 8, 1, 9},
		{"raw eats a statement", "let a = r\"abc\nlet b = 1;\n", 8, 1, 9},
		{"triple eats a statement", "let a = \"\"\"abc\nlet b = 1;\n", 8, 1, 9},
		{"raw triple eats a statement", "let a = r\"\"\"abc\nlet b = 1;\n", 8, 1, 9},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tok := onlyUnterminated(t, tt.src)
			if tok.Start.Offset != tt.openAt {
				t.Errorf("UNTERMINATED starts at offset %d, want %d (the literal's first character)",
					tok.Start.Offset, tt.openAt)
			}
			if tok.Start.Line != tt.openLine || tok.Start.Column != tt.openCol {
				t.Errorf("UNTERMINATED starts at %d:%d, want %d:%d",
					tok.Start.Line, tok.Start.Column, tt.openLine, tt.openCol)
			}
			for _, other := range allTokens(t, tt.src) {
				if other.Type == token.STRING || other.Type == token.TEMPLATE {
					t.Errorf("an unterminated literal still produced a %s valued %q",
						other.Type, other.Literal)
				}
			}
		})
	}
}

// M26-LEX-006, and the stream the row asks for by name.
func TestANULByteIsIllegalAndTheRestOfTheFileStillLexes(t *testing.T) {
	src := "a;" + string(rune(0)) + "b;"
	toks := allTokens(t, src)

	want := []token.TokenType{
		token.IDENT, token.SEMICOLON, token.ILLEGAL,
		token.IDENT, token.SEMICOLON, token.EOF,
	}
	if got := types(toks); got != "IDENT ; ILLEGAL IDENT ; EOF" {
		t.Fatalf("token stream = %q, want %q", got, "IDENT ; ILLEGAL IDENT ; EOF")
	}
	for i, w := range want {
		if toks[i].Type != w {
			t.Fatalf("token %d is %s, want %s", i, toks[i].Type, w)
		}
	}
	if toks[0].Literal != "a" || toks[3].Literal != "b" {
		t.Errorf("identifiers are %q and %q, want \"a\" and \"b\"", toks[0].Literal, toks[3].Literal)
	}
	if toks[2].Start.Offset != 2 || toks[2].End.Offset != 3 {
		t.Errorf("the ILLEGAL token spans offsets %d..%d, want 2..3 (the NUL alone)",
			toks[2].Start.Offset, toks[2].End.Offset)
	}
	if !strings.Contains(toks[2].Err, "NUL") {
		t.Errorf("Err = %q, want it to name the NUL byte", toks[2].Err)
	}
}

// M26-LEX-006's worst spelling: a NUL inside a comment ended the comment, and
// the lexer read that as the end of the file. The whole program after it
// vanished -- 0 statements, 0 errors -- and `mutant fmt` wrote the comment back
// over the file as its entire contents.
func TestANULByteInACommentDoesNotEndTheFile(t *testing.T) {
	src := "// hi" + string(rune(0)) + "\nlet a = 1;\n"
	toks := allTokens(t, src)

	if got, want := types(toks), "ILLEGAL LET IDENT = INT ; EOF"; got != want {
		t.Fatalf("token stream = %q, want %q", got, want)
	}
	if toks[0].Start.Offset != 5 {
		t.Errorf("the ILLEGAL token starts at offset %d, want 5 (the NUL)", toks[0].Start.Offset)
	}
	if !strings.Contains(toks[0].Err, "NUL") {
		t.Errorf("Err = %q, want it to name the NUL byte", toks[0].Err)
	}

	// The comment is still trivia, and still recorded: the byte is reported
	// after the comment is consumed whole, so the formatter's comment table is
	// unaffected and the error costs one token rather than a statement made
	// out of the comment's words.
	l := New(src)
	for i := 0; i <= len(src)+16; i++ {
		if l.NextToken().Type == token.EOF {
			break
		}
	}
	if got := len(l.Comments()); got != 1 {
		t.Fatalf("%d comments recorded, want 1", got)
	}
	if got := l.Comments()[0].Text; got != "// hi"+string(rune(0)) {
		t.Errorf("comment text = %q, want the whole comment including the byte", got)
	}
}

// A NUL inside a literal is refused rather than carried, because decodeParts
// masks each hole of a triple-quoted template with a NUL and splits the block
// on it -- an invariant its own comment states and nothing used to enforce.
//
// The `"a\<NUL>b"` case is the reason the check lives in readStringToken and
// not in the body scanners: a scan steps over the character after a backslash
// without looking at it, so a per-scan check cannot see that byte.
func TestANULByteInsideAStringLiteralIsIllegal(t *testing.T) {
	nul := string(rune(0))
	cases := []struct {
		name string
		src  string
		next token.TokenType // what follows the literal, to prove the scan found its end
	}{
		{"ordinary", `"x` + nul + `y";`, token.SEMICOLON},
		{"raw", `r"x` + nul + `y";`, token.SEMICOLON},
		{"triple", `"""x` + nul + `y""";`, token.SEMICOLON},
		{"raw triple", `r"""x` + nul + `y""";`, token.SEMICOLON},
		{"template", `"""p${1}q` + nul + `r""";`, token.SEMICOLON},
		{"after a backslash", `"a\` + nul + `b";`, token.SEMICOLON},
		{"inside a hole", `"${ f(` + nul + `) }";`, token.SEMICOLON},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tok := onlyIllegal(t, tt.src)
			if !strings.Contains(tok.Err, "NUL") {
				t.Errorf("Err = %q, want it to name the NUL byte", tok.Err)
			}
			toks := allTokens(t, tt.src)
			if len(toks) < 2 || toks[1].Type != tt.next {
				t.Fatalf("the literal did not end where it ends: stream = %q", types(toks))
			}
		})
	}
}

// M26-LEX-017. scanHole's comment promised "the resulting error points inside
// the string", and there was no error at all: the hole was closed here, at the
// end of the literal, so `let a = """v=${1+2""";` compiled and set a to v=3.
func TestAnUnterminatedHoleIsIllegalAndSaysWhy(t *testing.T) {
	cases := []struct{ name, src string }{
		{"triple", `let a = """v=${1+2""";`},
		{"triple with a bracket", `let a = """v=${ h["k" """;`},
		{"ordinary", `let a = "v=${1+2";`},
		{"nested brace", `let a = """${ { 1: 2 """;`},
		{"multiline", "let a = \"\"\"\n  ${ 1\n\"\"\";"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tok := onlyIllegal(t, tt.src)
			if !strings.Contains(tok.Err, "unterminated ${") {
				t.Errorf("Err = %q, want it to name the unterminated ${", tok.Err)
			}
			for _, other := range allTokens(t, tt.src) {
				if other.Type == token.TEMPLATE {
					t.Errorf("an unterminated hole still produced a TEMPLATE with %d parts",
						len(other.Parts))
				}
			}
		})
	}
}

// The structural half of M26-LEX-006, stated as the invariant rather than as a
// symptom: end of input is a position, so the lexer consumes every byte of the
// file. l.ch == 0 could not express this, because a NUL byte decodes to 0 too.
func TestTheLexerConsumesEveryByteOfTheFile(t *testing.T) {
	nul := string(rune(0))
	sources := []string{
		"a;" + nul + "b;",
		"let a = 1;" + nul + "let b = 2;\nputln(b);\n",
		"// hi" + nul + "\nlet a = 1;\n",
		`"x` + nul + `y";`,
		`"""p${1}q` + nul + `r""";`,
		nul,
		nul + nul + nul,
		"let a = 1;" + nul,
		`"abc`,
		`let x = 1;`,
		``,
	}

	for _, src := range sources {
		t.Run(strings.ReplaceAll(src, nul, "<NUL>"), func(t *testing.T) {
			toks := allTokens(t, src)
			eof := toks[len(toks)-1]
			if eof.Start.Offset != len(src) {
				t.Errorf("EOF is at offset %d, want %d: the lexer stopped %d bytes early",
					eof.Start.Offset, len(src), len(src)-eof.Start.Offset)
			}
		})
	}
}

// The fix refuses more than it used to, so what it must NOT refuse is worth a
// test of its own. \0 is still how a string holds a NUL, and every other
// spelling still lexes to the value it did at a812eee.
func TestWellFormedLiteralsAreUntouched(t *testing.T) {
	cases := []struct {
		src     string
		want    token.TokenType
		literal string
	}{
		{`""`, token.STRING, ``},
		{`"abc"`, token.STRING, `abc`},
		{`"a\nb"`, token.STRING, "a\nb"},
		{`"a\0b"`, token.STRING, "a" + string(rune(0)) + "b"},
		{`"\0"`, token.STRING, string(rune(0))},
		{`r"C:\Users"`, token.STRING, `C:\Users`},
		{`""""""`, token.STRING, ``},
		{`"""abc"""`, token.STRING, `abc`},
		{`r"""a"b"""`, token.STRING, `a"b`},
		{`"\${x}"`, token.STRING, `${x}`},
		{`"${x}"`, token.TEMPLATE, `${x}`},
		{`"${ h["k"] }"`, token.TEMPLATE, `${ h["k"] }`},
		{`"host=${h} port=${p}"`, token.TEMPLATE, `host=${h} port=${p}`},
		{`"""a${x}b"""`, token.TEMPLATE, `a${x}b`},
	}

	for _, tt := range cases {
		t.Run(tt.src, func(t *testing.T) {
			tok := New(tt.src).NextToken()
			if tok.Type != tt.want {
				t.Fatalf("%q lexed as %s (Err %q), want %s", tt.src, tok.Type, tok.Err, tt.want)
			}
			if tok.Literal != tt.literal {
				t.Errorf("literal = %q, want %q", tok.Literal, tt.literal)
			}
			if tok.Err != "" {
				t.Errorf("Err = %q, want empty on a well-formed literal", tok.Err)
			}
		})
	}
}
