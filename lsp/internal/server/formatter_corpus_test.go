package server

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
			// The formatter refuses an example that does not parse, which
			// this test is not about.
			continue
		}

		once := mustFormat(t, path, snapshot)

		reparsed := analyzer.New().Analyze(once)
		if len(reparsed.ParseErrors) > 0 {
			t.Errorf("%s: formatted output no longer parses: %v", path, reparsed.ParseErrors[0])
			continue
		}

		if twice := mustFormat(t, path, reparsed); once != twice {
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
		after := commentBodies(mustFormat(t, path, snapshot))

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

// TestFormatterPreservesProgramStructureAcrossExamples is the check the other
// two cannot make.
//
// Idempotency proves formatting is stable and the comment count proves nothing
// was dropped from the side table, but a printer that lost a statement, swapped
// two of them, or re-associated an operator would satisfy both: its output is
// still stable, and it still carries every comment. What neither pins down is
// that the formatted text still means what the original did.
//
// The comparison is between parse trees rather than token streams, because this
// formatter legitimately rewrites tokens: it prints two pairs of brackets around
// one expression as one (`((a))` as `(a)`) and drops the optional terminator
// after a struct or enum declaration. Both keep the same tree, which is the
// property that actually matters. Re-parsing the formatted text and comparing
// renderings sees past all of it, and still catches a lost statement or a
// re-associated operator.
func TestFormatterPreservesProgramStructureAcrossExamples(t *testing.T) {
	compared, skipped := 0, 0

	for _, path := range exampleFiles(t) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}

		snapshot := analyzer.New().Analyze(string(data))
		if len(snapshot.ParseErrors) > 0 || snapshot.Program == nil {
			skipped++
			continue
		}

		formatted := mustFormat(t, path, snapshot)
		reparsed := analyzer.New().Analyze(formatted)
		if len(reparsed.ParseErrors) > 0 || reparsed.Program == nil {
			t.Errorf("%s: formatted output no longer parses: %v", path, reparsed.ParseErrors)
			continue
		}

		compared++
		before := canonicalRendering(snapshot.Program.String())
		after := canonicalRendering(reparsed.Program.String())
		if before == after {
			continue
		}
		t.Errorf("%s: formatting changed the program's structure\n%s", path, firstDifference(before, after))
	}

	if compared == 0 {
		t.Fatal("no example parsed cleanly enough to compare; the corpus or the analyzer is broken")
	}
	// The other corpus tests skip unparseable examples silently, which quietly
	// overstates how much of the corpus they cover. Say it out loud instead.
	t.Logf("compared the structure of %d examples; %d skipped as unparseable", compared, skipped)
}

// TestCanonicalRenderingDetectsRealChanges keeps the corpus check above from
// passing vacuously.
//
// A canonicaliser that over-normalised — collapsing everything to the same
// string, or sorting statements as well as hash pairs — would make the corpus
// test agree with itself no matter what the formatter did. These cases pin both
// halves: what it must treat as equal, and what it must not.
func TestCanonicalRenderingDetectsRealChanges(t *testing.T) {
	render := func(src string) string {
		snapshot := analyzer.New().Analyze(src)
		if len(snapshot.ParseErrors) > 0 {
			t.Fatalf("fixture %q did not parse: %v", src, snapshot.ParseErrors)
		}
		return canonicalRendering(snapshot.Program.String())
	}

	t.Run("hash pair order is not a difference", func(t *testing.T) {
		if a, b := render(`let h = {"a": 1, "b": 2};`), render(`let h = {"b": 2, "a": 1};`); a != b {
			t.Errorf("the same hash written in two orders rendered differently:\n  %s\n  %s", a, b)
		}
	})

	for _, tc := range []struct {
		name  string
		left  string
		right string
	}{
		{"a dropped statement", `let a = 1; let b = 2;`, `let a = 1;`},
		{"reordered statements", `let a = 1; let b = 2;`, `let b = 2; let a = 1;`},
		{"a re-associated operator", `let a = 1 + 2 * 3;`, `let a = (1 + 2) * 3;`},
		{"a changed hash value", `let h = {"a": 1};`, `let h = {"a": 2};`},
		{"a changed hash key", `let h = {"a": 1};`, `let h = {"b": 1};`},
		{"reordered array elements", `let a = [1, 2];`, `let a = [2, 1];`},
		{"a dropped argument", `putln(1, 2);`, `putln(1);`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if a, b := render(tc.left), render(tc.right); a == b {
				t.Errorf("%s was not detected; both rendered as %s", tc.name, a)
			}
		})
	}
}

// canonicalRendering makes an AST rendering comparable by sorting the members
// of every brace group.
//
// HashLiteral.Pairs holds its pairs in the order the author wrote them, and
// HashLiteral.String() renders that order, so one tree renders the same way
// every run -- which is what used to make the comparison below meaningless,
// back when the pairs were a Go map and no two renderings agreed on an order.
// The sorting here is no longer what rescues a hash literal, and stays because
// it costs nothing and makes the comparison one of membership rather than of
// order. Sorting is safe because braces are the
// one construct whose order carries no meaning:
// BlockStatement.String() concatenates its statements with no braces at all,
// and arrays — where order does matter — render with brackets. (Only tests
// render an AST; both engines evaluate a hash literal's pairs in the order the
// tree holds them, so the bytecode is unaffected either way.)
func canonicalRendering(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		switch s[i] {
		case '"':
			end := skipStringLiteral(s, i)
			b.WriteString(s[i:end])
			i = end
		case '{':
			end := matchingBrace(s, i)
			members := splitTopLevel(s[i+1 : end-1])
			for j := range members {
				members[j] = canonicalRendering(strings.TrimSpace(members[j]))
			}
			sort.Strings(members)
			b.WriteByte('{')
			b.WriteString(strings.Join(members, ", "))
			b.WriteByte('}')
			i = end
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

// skipStringLiteral returns the index just past the string literal starting at
// open, so quoted braces and commas are never treated as structure.
func skipStringLiteral(s string, open int) int {
	for i := open + 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return len(s)
}

// matchingBrace returns the index just past the '}' closing the '{' at open.
func matchingBrace(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '"':
			i = skipStringLiteral(s, i) - 1
		case '{':
			depth++
		case '}':
			if depth--; depth == 0 {
				return i + 1
			}
		}
	}
	return len(s)
}

// splitTopLevel splits on commas that are not inside a nested group or string.
func splitTopLevel(s string) []string {
	parts := make([]string, 0, 4)
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			i = skipStringLiteral(s, i) - 1
		case '{', '[', '(':
			depth++
		case '}', ']', ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	if rest := s[start:]; strings.TrimSpace(rest) != "" || len(parts) > 0 {
		parts = append(parts, rest)
	}
	return parts
}

// firstDifference locates where two renderings diverge and quotes a window
// around it, so a failure points at the construct that changed rather than
// dumping two whole programs.
func firstDifference(before, after string) string {
	limit := len(before)
	if len(after) < limit {
		limit = len(after)
	}
	at := limit
	for i := 0; i < limit; i++ {
		if before[i] != after[i] {
			at = i
			break
		}
	}

	start := at - 70
	if start < 0 {
		start = 0
	}
	window := func(s string) string {
		end := at + 70
		if end > len(s) {
			end = len(s)
		}
		return s[start:end]
	}
	return fmt.Sprintf("  at offset %d (%d chars before, %d after)\n  before: ...%s...\n  after:  ...%s...",
		at, len(before), len(after), window(before), window(after))
}

// TestFormatterAddsNoBracketsAcrossExamples holds every real example to the
// owner's decision of 2026-09-29: the formatter keeps the brackets the author
// wrote and adds none. The formatted text may have fewer `(` than the source --
// two pairs around one expression print as one -- and never more.
func TestFormatterAddsNoBracketsAcrossExamples(t *testing.T) {
	compared := 0
	for _, path := range exampleFiles(t) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		snapshot := analyzer.New().Analyze(string(data))
		if len(snapshot.ParseErrors) > 0 || snapshot.Program == nil {
			continue
		}
		compared++
		before := openingBrackets(string(data))
		if after := openingBrackets(mustFormat(t, path, snapshot)); after > before {
			t.Errorf("%s: formatting added brackets: %d before, %d after", path, before, after)
		}
	}
	if compared == 0 {
		t.Fatal("no example parsed cleanly enough to compare; the corpus or the analyzer is broken")
	}
}

// openingBrackets counts `(` tokens, so a bracket inside a string or a comment
// is not one.
func openingBrackets(src string) int {
	l := lexer.New(src)
	count := 0
	for tok := l.NextToken(); tok.Type != token.EOF; tok = l.NextToken() {
		if tok.Type == token.LPAREN {
			count++
		}
	}
	return count
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

// mustFormat is formatSnapshotText for a snapshot the caller has already
// checked parses, which is every use in this file. A refusal there would mean
// the formatter declined a tree it has no reason to decline, so it is a
// failure and not a skip.
func mustFormat(t *testing.T, path string, snapshot *analyzer.Snapshot) string {
	t.Helper()
	formatted, parseErrors, ok := formatSnapshotText(snapshot)
	if !ok {
		t.Fatalf("%s: the formatter refused a snapshot with no parse errors: %v", path, parseErrors)
	}
	return formatted
}
