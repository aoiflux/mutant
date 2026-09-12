package lexer

import (
	"testing"

	"mutant/token"
)

// firstString lexes src and returns the first STRING token's decoded value.
func firstString(t *testing.T, src string) token.Token {
	t.Helper()
	lex := New(src)
	for {
		tok := lex.NextToken()
		if tok.Type == token.STRING {
			return tok
		}
		if tok.Type == token.EOF {
			t.Fatalf("no string token in %q", src)
		}
	}
}

func TestOrdinaryStringEscapesAreUnchanged(t *testing.T) {
	cases := []struct{ src, want string }{
		{`"plain"`, "plain"},
		{`"a\nb"`, "a\nb"},
		{`"a\tb"`, "a\tb"},
		{`"a\"b"`, `a"b`},
		{`"a\\b"`, `a\b`},
		{`"C:\\Users\\Public"`, `C:\Users\Public`},
		{`"\w+\d"`, `\w+\d`}, // unknown escapes stay both characters
		{`""`, ""},
	}
	for _, tc := range cases {
		if got := firstString(t, tc.src).Literal; got != tc.want {
			t.Errorf("%s decoded to %q, want %q", tc.src, got, tc.want)
		}
	}
}

func TestDollarEscapeYieldsALoneDollar(t *testing.T) {
	// A lone $ is untouched, so only the two characters ${ ever need escaping.
	if got := firstString(t, `"cost: $5"`).Literal; got != "cost: $5" {
		t.Errorf("got %q", got)
	}
	if got := firstString(t, `"\${x}"`).Literal; got != "${x}" {
		t.Errorf("got %q, want a literal ${x}", got)
	}
}

func TestRawStringKeepsEveryBackslash(t *testing.T) {
	cases := []struct{ src, want string }{
		{`r"C:\Users\Public\AppData"`, `C:\Users\Public\AppData`},
		{`r"\\?\GLOBALROOT\Device"`, `\\?\GLOBALROOT\Device`},
		{`r"\d{4}-\d{2}-\d{2}"`, `\d{4}-\d{2}-\d{2}`},
		{`r""`, ""},
		{`r"${x}"`, "${x}"}, // raw means raw: no interpolation either
	}
	for _, tc := range cases {
		if got := firstString(t, tc.src).Literal; got != tc.want {
			t.Errorf("%s decoded to %q, want %q", tc.src, got, tc.want)
		}
	}
}

func TestRawPrefixDoesNotSwallowIdentifiers(t *testing.T) {
	// `r` only means "raw" when a quote follows it immediately. Every other
	// identifier starting with r has to keep lexing as an identifier.
	lex := New(`let rows = r; let r = 1;`)
	var idents []string
	for tok := lex.NextToken(); tok.Type != token.EOF; tok = lex.NextToken() {
		if tok.Type == token.IDENT {
			idents = append(idents, tok.Literal)
		}
		if tok.Type == token.STRING {
			t.Fatalf("lexed a string from %q", tok.Literal)
		}
	}
	want := []string{"rows", "r", "r"}
	if len(idents) != len(want) {
		t.Fatalf("got idents %v, want %v", idents, want)
	}
	for i := range want {
		if idents[i] != want[i] {
			t.Fatalf("got idents %v, want %v", idents, want)
		}
	}
}

func TestTripleQuotedSpansLines(t *testing.T) {
	src := "\"\"\"\nalpha\nbeta\n\"\"\""
	if got := firstString(t, src).Literal; got != "alpha\nbeta" {
		t.Errorf("got %q", got)
	}
}

func TestTripleQuotedStripsInheritedIndentation(t *testing.T) {
	// The closing delimiter's own indentation says where the left margin is,
	// which is what makes a block readable inside an indented body.
	src := "let banner = \"\"\"\n\t\tRULE alpha\n\t\t  detail\n\t\t\"\"\";"
	if got := firstString(t, src).Literal; got != "RULE alpha\n  detail" {
		t.Errorf("got %q", got)
	}
}

func TestTripleQuotedWithTextOnTheOpeningLineIsNotReindented(t *testing.T) {
	src := "\"\"\"alpha\n  beta\"\"\""
	if got := firstString(t, src).Literal; got != "alpha\n  beta" {
		t.Errorf("got %q", got)
	}
}

func TestTripleQuotedNormalizesCRLF(t *testing.T) {
	// A checkout's line endings must not change what a program means.
	src := "\"\"\"\r\nalpha\r\nbeta\r\n\"\"\""
	if got := firstString(t, src).Literal; got != "alpha\nbeta" {
		t.Errorf("got %q", got)
	}
}

func TestTripleQuotedHoldsLooseQuotes(t *testing.T) {
	src := "\"\"\"\nhe said \"hi\" and \"\" too\n\"\"\""
	if got := firstString(t, src).Literal; got != `he said "hi" and "" too` {
		t.Errorf("got %q", got)
	}
}

func TestRawTripleQuotedKeepsBackslashesAndQuotes(t *testing.T) {
	src := "r\"\"\"\nrule x { strings: $a = \"C:\\Windows\\\" }\n\"\"\""
	want := `rule x { strings: $a = "C:\Windows\" }`
	if got := firstString(t, src).Literal; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTripleQuotedStillProcessesEscapes(t *testing.T) {
	src := "\"\"\"\na\\tb\n\"\"\""
	if got := firstString(t, src).Literal; got != "a\tb" {
		t.Errorf("got %q", got)
	}
}

func TestEmptyStringIsNotATripleQuote(t *testing.T) {
	lex := New(`"" + "x"`)
	first := lex.NextToken()
	if first.Type != token.STRING || first.Literal != "" {
		t.Fatalf("got %v %q", first.Type, first.Literal)
	}
	if plus := lex.NextToken(); plus.Type != token.PLUS {
		t.Fatalf("got %v after the empty string, want +", plus.Type)
	}
}

func TestTripleQuotedTokenSpansItsWholeRange(t *testing.T) {
	// The token's End has to sit past the closing delimiter, or every position
	// after a multi-line literal is wrong.
	src := "\"\"\"\nalpha\n\"\"\";"
	tok := firstString(t, src)
	if tok.Start.Line != 1 {
		t.Errorf("start line %d, want 1", tok.Start.Line)
	}
	if tok.End.Line != 3 {
		t.Errorf("end line %d, want 3", tok.End.Line)
	}
	if tok.End.Offset != len(src)-1 {
		t.Errorf("end offset %d, want %d", tok.End.Offset, len(src)-1)
	}
}

func TestUnterminatedLiteralsDoNotHang(t *testing.T) {
	for _, src := range []string{`"abc`, `r"abc`, `"""abc`, `r"""abc`, `"abc\`} {
		lex := New(src)
		for i := 0; ; i++ {
			tok := lex.NextToken()
			if tok.Type == token.EOF {
				break
			}
			if i > 16 {
				t.Fatalf("%q produced a token loop", src)
			}
		}
	}
}

// templateParts lexes src and returns the first TEMPLATE token.
func templateToken(t *testing.T, src string) token.Token {
	t.Helper()
	lex := New(src)
	for {
		tok := lex.NextToken()
		if tok.Type == token.TEMPLATE {
			return tok
		}
		if tok.Type == token.EOF {
			t.Fatalf("no template token in %q", src)
		}
	}
}

func describeParts(parts []token.StringPart) string {
	out := ""
	for _, part := range parts {
		if part.Expression {
			out += "{" + part.Text + "}"
			continue
		}
		out += "[" + part.Text + "]"
	}
	return out
}

func TestTemplateSplitsTextFromHoles(t *testing.T) {
	cases := []struct{ src, want string }{
		{`"host=${h} port=${p}"`, "[host=]{h}[ port=]{p}"},
		{`"${x}"`, "{x}"},
		{`"${a}${b}"`, "{a}{b}"},
		{`"a${ f(1, 2) }b"`, "[a]{ f(1, 2) }[b]"},
		{`"${ h["k"] }"`, `{ h["k"] }`},
		{`"${ outer(${})}"`, "{ outer(${})}"},
	}
	for _, tc := range cases {
		if got := describeParts(templateToken(t, tc.src).Parts); got != tc.want {
			t.Errorf("%s split to %s, want %s", tc.src, got, tc.want)
		}
	}
}

func TestStringWithoutAHoleStaysAString(t *testing.T) {
	for _, src := range []string{`"plain"`, `"cost: $5"`, `"\${x}"`, `r"${x}"`} {
		lex := New(src)
		if tok := lex.NextToken(); tok.Type != token.STRING {
			t.Errorf("%s lexed as %v, want STRING", src, tok.Type)
		}
	}
}

func TestHolePositionsPointIntoTheString(t *testing.T) {
	// `let s = "n=${n}";` -- the hole’s `n` is at column 14.
	tok := templateToken(t, `let s = "n=${n}";`)
	var hole token.StringPart
	for _, part := range tok.Parts {
		if part.Expression {
			hole = part
		}
	}
	if hole.Start.Line != 1 || hole.Start.Column != 14 {
		t.Errorf("hole at %d:%d, want 1:14", hole.Start.Line, hole.Start.Column)
	}
	if hole.Start.Offset != 13 {
		t.Errorf("hole offset %d, want 13", hole.Start.Offset)
	}
}

func TestTripleQuotedTemplateIsReindentedAroundItsHoles(t *testing.T) {
	src := "let s = \"\"\"\n    name: ${n}\n    id:   ${i}\n    \"\"\";"
	got := describeParts(templateToken(t, src).Parts)
	want := "[name: ]{n}[\nid:   ]{i}"
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestHoleOnALaterLineReportsThatLine(t *testing.T) {
	src := "\"\"\"\nalpha\nbeta ${x}\n\"\"\""
	for _, part := range templateToken(t, src).Parts {
		if !part.Expression {
			continue
		}
		if part.Start.Line != 3 {
			t.Errorf("hole on line %d, want 3", part.Start.Line)
		}
	}
}

func TestTemplateKeepsItsSpelling(t *testing.T) {
	src := `"host=${h}"`
	if raw := templateToken(t, src).Raw; raw != src {
		t.Errorf("raw spelling %q, want %q", raw, src)
	}
}
