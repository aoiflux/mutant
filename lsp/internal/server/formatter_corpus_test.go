package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/lexer"
	"mutant/lsp/internal/analyzer"
	"mutant/token"
)

// exampleFiles collects the repository's example programs. These are real
// Mutant sources rather than hand-written fixtures, which makes them the
// best available guard against the formatter regressing on shapes the unit
// tests do not happen to cover.
func exampleFiles(t *testing.T) []string {
	t.Helper()

	root := filepath.Join("..", "..", "..", "examples")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("examples directory not available: %v", err)
	}

	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".mut") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	if len(files) == 0 {
		t.Skip("no example programs found")
	}
	return files
}

// TestFormatterIsIdempotentAcrossExamples is the strongest idempotency check
// available: format every real example, re-parse the result, format again,
// and require the two passes to agree byte for byte. A formatter that is not
// idempotent makes format-on-save produce diff churn forever.
func TestFormatterIsIdempotentAcrossExamples(t *testing.T) {
	for _, path := range exampleFiles(t) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}

		snapshot := analyzer.New().Analyze(string(data))
		if len(snapshot.ParseErrors) > 0 {
			// Unparseable examples take the whitespace-normalisation path,
			// which this test is not about.
			continue
		}

		once := formatSnapshotText(snapshot)

		reparsed := analyzer.New().Analyze(once)
		if len(reparsed.ParseErrors) > 0 {
			t.Errorf("%s: formatted output no longer parses: %v", path, reparsed.ParseErrors[0])
			continue
		}

		if twice := formatSnapshotText(reparsed); once != twice {
			t.Errorf("%s: formatting is not idempotent", path)
		}
	}
}

// TestFormatterPreservesEveryCommentAcrossExamples guards the riskiest part
// of the printer. Comments live outside the AST, so they are re-attached by
// walking a position-ordered side table; an off-by-one in that cursor would
// silently delete a comment. Counting them before and after catches that.
func TestFormatterPreservesEveryCommentAcrossExamples(t *testing.T) {
	for _, path := range exampleFiles(t) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}

		src := string(data)
		snapshot := analyzer.New().Analyze(src)
		if len(snapshot.ParseErrors) > 0 {
			continue
		}

		before := commentBodies(src)
		after := commentBodies(formatSnapshotText(snapshot))

		if len(before) != len(after) {
			t.Errorf("%s: %d comments before formatting, %d after", path, len(before), len(after))
			continue
		}
		for i := range before {
			if before[i] != after[i] {
				t.Errorf("%s: comment %d changed from %q to %q", path, i, before[i], after[i])
			}
		}
	}
}

// commentBodies lexes src and returns its comment texts in source order.
func commentBodies(src string) []string {
	l := lexer.New(src)
	for {
		if tok := l.NextToken(); tok.Type == token.EOF {
			break
		}
	}

	comments := l.Comments()
	out := make([]string, 0, len(comments))
	for _, comment := range comments {
		out = append(out, strings.TrimSpace(comment.Text))
	}
	return out
}
