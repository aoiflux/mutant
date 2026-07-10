package lexer

import (
	"mutant/token"
	"testing"
)

// TestTokenPositions verifies that every token produced by the lexer carries
// accurate 1-based line/column and 0-based offset information for both its
// Start and End positions. The End position is LSP-exclusive: it points one
// past the final character of the token.
func TestTokenPositions(t *testing.T) {
	// Source layout (offsets in comments):
	//   line 1: "let x = 5;"    (offsets 0..9, newline at 10)
	//   line 2: "let ab = 12;"  (offsets 11..22, newline at 23)
	//   line 3: `"hi"`          (offsets 24..27)
	input := "let x = 5;\nlet ab = 12;\n\"hi\""

	type want struct {
		typ       token.TokenType
		literal   string
		startLine int
		startCol  int
		startOff  int
		endLine   int
		endCol    int
		endOff    int
	}

	tests := []want{
		// line 1
		{token.LET, "let", 1, 1, 0, 1, 4, 3},
		{token.IDENT, "x", 1, 5, 4, 1, 6, 5},
		{token.ASSIGN, "=", 1, 7, 6, 1, 8, 7},
		{token.INT, "5", 1, 9, 8, 1, 10, 9},
		{token.SEMICOLON, ";", 1, 10, 9, 1, 11, 10},
		// line 2
		{token.LET, "let", 2, 1, 11, 2, 4, 14},
		{token.IDENT, "ab", 2, 5, 15, 2, 7, 17},
		{token.ASSIGN, "=", 2, 8, 18, 2, 9, 19},
		{token.INT, "12", 2, 10, 20, 2, 12, 22},
		{token.SEMICOLON, ";", 2, 12, 22, 2, 13, 23},
		// line 3
		{token.STRING, "hi", 3, 1, 24, 3, 5, 28},
	}

	l := New(input)
	for i, w := range tests {
		tok := l.NextToken()
		if tok.Type != w.typ {
			t.Fatalf("tests[%d]: type mismatch: got %q want %q", i, tok.Type, w.typ)
		}
		if tok.Literal != w.literal {
			t.Fatalf("tests[%d]: literal mismatch: got %q want %q", i, tok.Literal, w.literal)
		}
		if tok.Start.Line != w.startLine || tok.Start.Column != w.startCol || tok.Start.Offset != w.startOff {
			t.Fatalf("tests[%d]: start mismatch: got {L:%d C:%d O:%d} want {L:%d C:%d O:%d}",
				i, tok.Start.Line, tok.Start.Column, tok.Start.Offset,
				w.startLine, w.startCol, w.startOff)
		}
		if tok.End.Line != w.endLine || tok.End.Column != w.endCol || tok.End.Offset != w.endOff {
			t.Fatalf("tests[%d]: end mismatch: got {L:%d C:%d O:%d} want {L:%d C:%d O:%d}",
				i, tok.End.Line, tok.End.Column, tok.End.Offset,
				w.endLine, w.endCol, w.endOff)
		}
	}
}

// TestTokenPositions_MultiCharOperators exercises the two-char operators
// (== and !=) which take a special path in NextToken.
func TestTokenPositions_MultiCharOperators(t *testing.T) {
	input := "a == b != c"
	//        0 234 6 89

	l := New(input)
	got := []token.Token{}
	for {
		tok := l.NextToken()
		if tok.Type == token.EOF {
			break
		}
		got = append(got, tok)
	}

	if len(got) != 5 {
		t.Fatalf("expected 5 tokens, got %d", len(got))
	}

	// "==" spans offsets 2..3 -> Start{1,3,2} End{1,5,4}
	eq := got[1]
	if eq.Type != token.EQUALITY || eq.Literal != "==" {
		t.Fatalf("token[1] not ==: %+v", eq)
	}
	if eq.Start.Column != 3 || eq.Start.Offset != 2 {
		t.Fatalf("== start wrong: %+v", eq.Start)
	}
	if eq.End.Column != 5 || eq.End.Offset != 4 {
		t.Fatalf("== end wrong: %+v", eq.End)
	}

	// "!=" spans offsets 7..8 -> Start{1,8,7} End{1,10,9}
	ne := got[3]
	if ne.Type != token.INEQUALITY || ne.Literal != "!=" {
		t.Fatalf("token[3] not !=: %+v", ne)
	}
	if ne.Start.Column != 8 || ne.Start.Offset != 7 {
		t.Fatalf("!= start wrong: %+v", ne.Start)
	}
	if ne.End.Column != 10 || ne.End.Offset != 9 {
		t.Fatalf("!= end wrong: %+v", ne.End)
	}
}

// TestTokenPositions_EOF verifies that EOF is a zero-width token at the end
// of input.
func TestTokenPositions_EOF(t *testing.T) {
	input := "abc"
	l := New(input)
	for {
		tok := l.NextToken()
		if tok.Type == token.EOF {
			if tok.Start.Offset != 3 || tok.End.Offset != 3 {
				t.Fatalf("EOF offsets: got Start=%d End=%d, want both 3", tok.Start.Offset, tok.End.Offset)
			}
			if tok.Start.Line != 1 || tok.End.Line != 1 {
				t.Fatalf("EOF line: got Start=%d End=%d, want both 1", tok.Start.Line, tok.End.Line)
			}
			return
		}
	}
}

// TestTokenPositions_CRLF ensures '\r\n' line endings advance the line only
// once (on the '\n') and keep column indices correct on the following line.
func TestTokenPositions_CRLF(t *testing.T) {
	input := "a\r\nb"
	l := New(input)

	a := l.NextToken()
	if a.Literal != "a" || a.Start.Line != 1 || a.Start.Column != 1 {
		t.Fatalf("token 'a' pos wrong: %+v", a)
	}

	b := l.NextToken()
	if b.Literal != "b" || b.Start.Line != 2 || b.Start.Column != 1 {
		t.Fatalf("token 'b' pos wrong: got %+v, want line=2 col=1", b)
	}
}
