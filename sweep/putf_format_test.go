package sweep

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/lexer"
	"mutant/token"
)

// No example decides putf's format at run time.
//
// putf reads its first argument as a format when that holds a `%`, so the
// format has to be a string the program wrote, with a verb for each value after
// it. The image examples built theirs with `+` -- `putf("  size=" + meta["size"])`
// -- which stops the program at the first value that is not a string, because
// `+` refuses STRING + INTEGER by design. They also passed the data they read
// as the format, `putf(content)`, which reads any `%` in the data as a verb.
// Because the sweep cannot supply a disk image it never ran them, and the first
// real disk anyone opened with one stopped with a runtime error (M26-EX-020).
// This check needs no image.
//
// The fix it asks for is the one the owner set on 2026-09-29: write the format
// out, `putf("  size=%d\n", meta["size"])`. str_format builds the same string
// without printing it.
func TestNoExampleBuildsAPutfFormatAtRunTime(t *testing.T) {
	examples := filepath.Join(repositoryRoot, "examples")
	checked := 0
	for _, path := range mutantPrograms(t) {
		if !strings.HasPrefix(filepath.ToSlash(path), filepath.ToSlash(examples)+"/") {
			continue
		}
		checked++

		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %s", path, err)
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, repositoryRoot+string(filepath.Separator)))
		for _, call := range putfCalls(string(source)) {
			if call.format.Type == token.STRING && (call.after.Type == token.COMMA || call.after.Type == token.RPAREN) {
				continue
			}
			t.Errorf("%s:%d: putf's format is decided at run time (it starts %s %q, then %s %q)"+
				"\n\twrite the format out with a verb for each value, as in putf(\"  size=%%d\\n\", meta[\"size\"])",
				rel, call.format.Start.Line, call.format.Type, call.format.Literal, call.after.Type, call.after.Literal)
		}
	}
	if checked == 0 {
		t.Fatal("found no examples; the walk is looking in the wrong place")
	}
}

// putfCall is a call to putf as the lexer sees it: the first token of its first
// argument, and the token after that.
type putfCall struct {
	format token.Token
	after  token.Token
}

// putfCalls finds every `putf(` in src that is not a field or namespace access.
func putfCalls(src string) []putfCall {
	var tokens []token.Token
	lex := lexer.New(src)
	for tok := lex.NextToken(); tok.Type != token.EOF; tok = lex.NextToken() {
		tokens = append(tokens, tok)
	}

	var calls []putfCall
	for i := 0; i+3 < len(tokens); i++ {
		if tokens[i].Type != token.IDENT || tokens[i].Literal != "putf" || tokens[i+1].Type != token.LPAREN {
			continue
		}
		if i > 0 && tokens[i-1].Type == token.DOT {
			continue
		}
		calls = append(calls, putfCall{format: tokens[i+2], after: tokens[i+3]})
	}
	return calls
}
