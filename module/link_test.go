package module

import (
	"path/filepath"
	"strings"
	"testing"
)

// firstStatementLine reports the blob line the module's first statement now
// claims, which is what the compiler will record and the VM will report.
func firstStatementLine(t *testing.T, mod *Module) int {
	t.Helper()

	if len(mod.Program.Statements) == 0 {
		t.Fatalf("%s has no statements to locate", mod.Display)
	}
	rng, ok := mod.Program.RangeOf(mod.Program.Statements[0])
	if !ok {
		t.Fatalf("%s recorded no range for its first statement", mod.Display)
	}
	return rng.Start.Line
}

func TestLinkConcatenatesInCompileOrder(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut": "import \"lib.mut\";\nlet main = 1;\n",
		"lib.mut":  "let lib = 1;\n",
	})

	g, err := Load(filepath.Join(root, "main.mut"), nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	linked := g.Link()

	want := "let lib = 1;\nimport \"lib.mut\";\nlet main = 1;\n"
	if linked.SourceText != want {
		t.Fatalf("linked source = %q, want %q", linked.SourceText, want)
	}
	if filepath.Base(linked.EntryPath) != "main.mut" {
		t.Fatalf("entry path = %q, want main.mut", linked.EntryPath)
	}
}

func TestLinkSpansCoverTheBlob(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut": "import \"a.mut\";\nimport \"b.mut\";\nlet main = 1;\n",
		"a.mut":    "let a1 = 1;\nlet a2 = 2;\n",
		"b.mut":    "let b1 = 1;\n",
	})

	g, err := Load(filepath.Join(root, "main.mut"), nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	linked := g.Link()

	if len(linked.Spans) != 3 {
		t.Fatalf("expected one span per module, got %d", len(linked.Spans))
	}

	// a.mut (2 lines), b.mut (1 line), main.mut (3 lines).
	wantStarts := []int{1, 3, 4}
	for i, span := range linked.Spans {
		if span.StartLine != wantStarts[i] {
			t.Fatalf("span %d (%s) starts at %d, want %d", i, span.Path, span.StartLine, wantStarts[i])
		}
	}

	totalLines := strings.Count(linked.SourceText, "\n")
	if totalLines != 6 {
		t.Fatalf("blob has %d lines, want 6", totalLines)
	}
}

// TestLinkShiftsPositionsOntoTheBlob is the test that matters: a statement on
// line 1 of main.mut must report the blob line its text actually occupies, or
// the traceback will quote a line of a different file.
func TestLinkShiftsPositionsOntoTheBlob(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut": "import \"a.mut\";\nlet main = 1;\n",
		"a.mut":    "let a1 = 1;\nlet a2 = 2;\n",
	})

	g, err := Load(filepath.Join(root, "main.mut"), nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	byName := func(name string) *Module {
		for _, mod := range g.Modules {
			if filepath.Base(mod.Path) == name {
				return mod
			}
		}
		t.Fatalf("%s not in the graph", name)
		return nil
	}

	beforeMain := firstStatementLine(t, byName("main.mut"))
	if beforeMain != 1 {
		t.Fatalf("before linking, main.mut's first statement is on line %d, want 1", beforeMain)
	}

	linked := g.Link()

	if got := firstStatementLine(t, byName("a.mut")); got != 1 {
		t.Fatalf("a.mut is linked first, so its first statement stays on line %d, got %d", 1, got)
	}
	// a.mut occupies blob lines 1-2, so main.mut's own line 1 is blob line 3.
	if got := firstStatementLine(t, byName("main.mut")); got != 3 {
		t.Fatalf("main.mut's first statement is on blob line %d, want 3", got)
	}

	// And the shifted line must actually name main.mut's text in the blob.
	lines := strings.Split(linked.SourceText, "\n")
	if !strings.Contains(lines[2], "import") {
		t.Fatalf("blob line 3 is %q, which is not main.mut's first line", lines[2])
	}
}

// TestLinkSeparatesModulesWithoutTrailingNewlines guards the case that would
// silently put two files' code on one blob line, where no span can tell them
// apart.
func TestLinkSeparatesModulesWithoutTrailingNewlines(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut": "import \"a.mut\";\nlet main = 1;",
		"a.mut":    "let a = 1;",
	})

	g, err := Load(filepath.Join(root, "main.mut"), nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	linked := g.Link()

	want := "let a = 1;\nimport \"a.mut\";\nlet main = 1;\n"
	if linked.SourceText != want {
		t.Fatalf("linked source = %q, want %q", linked.SourceText, want)
	}
	if linked.Spans[1].StartLine != 2 {
		t.Fatalf("main.mut starts at blob line %d, want 2", linked.Spans[1].StartLine)
	}
}

// TestLinkShiftsOffsetsAsWellAsLines pins the byte coordinate. Consumers that
// slice SourceText by Offset -- the formatter's comment placement among them --
// read the wrong bytes if only the line moves.
func TestLinkShiftsOffsetsAsWellAsLines(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut": "import \"a.mut\";\nlet main = 1;\n",
		"a.mut":    "let a = 1;\n",
	})

	g, err := Load(filepath.Join(root, "main.mut"), nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	linked := g.Link()

	entry := linked.Entry
	rng, ok := entry.Program.RangeOf(entry.Program.Statements[0])
	if !ok {
		t.Fatal("no range for the entry's first statement")
	}
	if got := linked.SourceText[rng.Start.Offset:rng.End.Offset]; !strings.HasPrefix(got, "import") {
		t.Fatalf("the entry's first statement slices to %q, want its import", got)
	}
}

// TestLinkShiftsComments covers the second of the three position side-tables.
// Shifting NodePositions alone would leave the formatter and every
// comment-aware tool pinning documentation to the wrong statements.
func TestLinkShiftsComments(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut": "import \"a.mut\";\n// leading comment\nlet main = 1;\n",
		"a.mut":    "let a = 1;\n",
	})

	g, err := Load(filepath.Join(root, "main.mut"), nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	entry := g.Entry
	if len(entry.Program.Comments) == 0 {
		t.Fatal("expected the entry to carry a comment")
	}
	before := entry.Program.Comments[0].Start.Line

	g.Link()

	after := entry.Program.Comments[0].Start.Line
	if after <= before {
		t.Fatalf("comment line did not move: %d -> %d", before, after)
	}
	// a.mut occupies blob line 1, so main.mut's line 2 comment is blob line 3.
	if after != 3 {
		t.Fatalf("comment is on blob line %d, want 3", after)
	}
	if line := strings.Split(linkedText(t, g), "\n")[after-1]; !strings.Contains(line, "leading comment") {
		t.Fatalf("blob line %d is %q, which is not where the comment lives", after, line)
	}
}

// linkedText re-derives the blob from an already-linked graph without shifting
// positions a second time.
func linkedText(t *testing.T, g *Graph) string {
	t.Helper()

	var b strings.Builder
	for _, mod := range g.Modules {
		b.WriteString(mod.Source)
		if !strings.HasSuffix(mod.Source, "\n") {
			b.WriteString("\n")
		}
	}
	return b.String()
}

// TestLinkOfASingleFileIsANoOp keeps the unlinked case honest: a one-module
// program must come out byte-identical with unshifted positions, so nothing
// about single-file compilation changes.
func TestLinkOfASingleFileIsANoOp(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut": "let x = 1;\nlet y = 2;\n",
	})

	g, err := Load(filepath.Join(root, "main.mut"), nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	linked := g.Link()

	if linked.SourceText != "let x = 1;\nlet y = 2;\n" {
		t.Fatalf("single-file blob = %q", linked.SourceText)
	}
	if len(linked.Spans) != 1 || linked.Spans[0].StartLine != 1 {
		t.Fatalf("expected one span starting at line 1, got %+v", linked.Spans)
	}
	if got := firstStatementLine(t, linked.Entry); got != 1 {
		t.Fatalf("a single file's positions must not move; first statement is on line %d", got)
	}
}

func TestLinkOfAnEmptyGraphIsSafe(t *testing.T) {
	var g *Graph
	if linked := g.Link(); linked == nil || linked.SourceText != "" {
		t.Fatal("linking a nil graph must produce an empty result, not panic")
	}
	if linked := (&Graph{}).Link(); len(linked.Spans) != 0 {
		t.Fatal("linking an empty graph must produce no spans")
	}
}
