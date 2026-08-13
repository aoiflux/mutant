package lexer

import (
	"mutant/token"
	"testing"
)

// drain runs the lexer to EOF so that its comment trivia is complete.
func drain(l *Lexer) {
	for {
		if tok := l.NextToken(); tok.Type == token.EOF {
			return
		}
	}
}

func TestCommentsAreCapturedWithPositions(t *testing.T) {
	// Offsets: `let x = 5; // hi` -> the first '/' sits at byte 11.
	input := "let x = 5; // hi\n// standalone\nlet y = 6;\n"

	l := New(input)
	drain(l)

	comments := l.Comments()
	if len(comments) != 2 {
		t.Fatalf("expected 2 comments, got %d: %#v", len(comments), comments)
	}

	tests := []struct {
		text        string
		startLine   int
		startColumn int
		startOffset int
		endOffset   int
	}{
		{"// hi", 1, 12, 11, 16},
		{"// standalone", 2, 1, 17, 30},
	}

	for i, want := range tests {
		got := comments[i]
		if got.Kind != token.LineComment {
			t.Errorf("comment %d: kind = %q, want %q", i, got.Kind, token.LineComment)
		}
		if got.Text != want.text {
			t.Errorf("comment %d: text = %q, want %q", i, got.Text, want.text)
		}
		if got.Start.Line != want.startLine {
			t.Errorf("comment %d: start line = %d, want %d", i, got.Start.Line, want.startLine)
		}
		if got.Start.Column != want.startColumn {
			t.Errorf("comment %d: start column = %d, want %d", i, got.Start.Column, want.startColumn)
		}
		if got.Start.Offset != want.startOffset {
			t.Errorf("comment %d: start offset = %d, want %d", i, got.Start.Offset, want.startOffset)
		}
		if got.End.Offset != want.endOffset {
			t.Errorf("comment %d: end offset = %d, want %d", i, got.End.Offset, want.endOffset)
		}
		// The recorded range must slice back to exactly the comment text.
		if sliced := input[got.Start.Offset:got.End.Offset]; sliced != want.text {
			t.Errorf("comment %d: input[start:end] = %q, want %q", i, sliced, want.text)
		}
	}
}

func TestCommentsDoNotAffectTokenStream(t *testing.T) {
	withComments := New("let // note\nx = 5; // tail\n")
	withoutComments := New("let x = 5;\n")

	for {
		got := withComments.NextToken()
		want := withoutComments.NextToken()

		if got.Type != want.Type || got.Literal != want.Literal {
			t.Fatalf("token mismatch: got {%s %q}, want {%s %q}", got.Type, got.Literal, want.Type, want.Literal)
		}
		if got.Type == token.EOF {
			return
		}
	}
}

func TestCommentMarkerInsideStringIsNotTrivia(t *testing.T) {
	l := New(`let url = "https://example.com";`)
	drain(l)

	if comments := l.Comments(); len(comments) != 0 {
		t.Fatalf("expected no comments, got %#v", comments)
	}
}

func TestTrailingCommentAtEOFIsCaptured(t *testing.T) {
	// No terminating newline: the comment runs to end of input.
	l := New("let x = 5; // end")
	drain(l)

	comments := l.Comments()
	if len(comments) != 1 {
		t.Fatalf("expected 1 comment, got %d: %#v", len(comments), comments)
	}
	if comments[0].Text != "// end" {
		t.Errorf("text = %q, want %q", comments[0].Text, "// end")
	}
}

func TestCRLFCommentDropsCarriageReturn(t *testing.T) {
	l := New("let x = 5; // hi\r\nlet y = 6;\r\n")
	drain(l)

	comments := l.Comments()
	if len(comments) != 1 {
		t.Fatalf("expected 1 comment, got %d: %#v", len(comments), comments)
	}
	if comments[0].Text != "// hi" {
		t.Errorf("text = %q, want %q (carriage return should be excluded)", comments[0].Text, "// hi")
	}
	// End must stay consistent with the trimmed text.
	if got := comments[0].End.Offset - comments[0].Start.Offset; got != len("// hi") {
		t.Errorf("range width = %d, want %d", got, len("// hi"))
	}
}

func TestOnlyCommentInputYieldsCommentAndEOF(t *testing.T) {
	l := New("// just a comment\n")

	if tok := l.NextToken(); tok.Type != token.EOF {
		t.Fatalf("expected EOF, got %s", tok.Type)
	}
	if comments := l.Comments(); len(comments) != 1 {
		t.Fatalf("expected 1 comment, got %#v", comments)
	}
}

func TestCommentIsTrailingClassification(t *testing.T) {
	// `let x = 5; // tail` then a standalone comment on the next line.
	input := "let x = 5; // tail\n// leading\nlet y = 6;\n"
	l := New(input)

	// Drive the lexer far enough to know where the `;` of the first
	// statement ends, which is the anchor a formatter would use.
	var semicolonEnd token.Position
	for {
		tok := l.NextToken()
		if tok.Type == token.SEMICOLON {
			semicolonEnd = tok.End
			break
		}
	}
	drain(l)

	comments := l.Comments()
	if len(comments) != 2 {
		t.Fatalf("expected 2 comments, got %d", len(comments))
	}
	if !comments[0].IsTrailing(semicolonEnd) {
		t.Errorf("comment %q should be trailing relative to %+v", comments[0].Text, semicolonEnd)
	}
	if comments[1].IsTrailing(semicolonEnd) {
		t.Errorf("comment %q should not be trailing (it is on a later line)", comments[1].Text)
	}
}
