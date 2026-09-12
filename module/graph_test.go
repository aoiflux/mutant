package module

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTree creates the named files under a fresh temporary directory and
// returns its path. Keys are slash-separated relative paths.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()

	root := t.TempDir()
	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", full, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	return root
}

func displayNames(g *Graph) []string {
	names := make([]string, 0, len(g.Modules))
	for _, mod := range g.Modules {
		names = append(names, filepath.Base(mod.Path))
	}
	return names
}

func TestLoadReturnsPostOrder(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut": "import \"a.mut\";\nimport \"b.mut\";\nlet x = 1;\n",
		"a.mut":    "import \"c.mut\";\nlet a = 1;\n",
		"b.mut":    "import \"c.mut\";\nlet b = 1;\n",
		"c.mut":    "let c = 1;\n",
	})

	g, err := Load(filepath.Join(root, "main.mut"), nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	got := displayNames(g)
	want := []string{"c.mut", "a.mut", "b.mut", "main.mut"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("compile order = %v, want %v", got, want)
	}

	if g.Entry != g.Modules[len(g.Modules)-1] {
		t.Fatal("the entry module must be last, after everything it imports")
	}
}

// TestLoadCompilesADiamondOnce pins the reason modules are keyed by file
// rather than by import: c.mut is reached from both a.mut and b.mut, and
// compiling it twice would give duplicate definitions for correct code.
func TestLoadCompilesADiamondOnce(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut": "import \"a.mut\";\nimport \"b.mut\";\n",
		"a.mut":    "import \"c.mut\";\n",
		"b.mut":    "import \"c.mut\";\n",
		"c.mut":    "let c = 1;\n",
	})

	g, err := Load(filepath.Join(root, "main.mut"), nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	seen := 0
	for _, mod := range g.Modules {
		if filepath.Base(mod.Path) == "c.mut" {
			seen++
		}
	}
	if seen != 1 {
		t.Fatalf("c.mut appears %d times in the compile order, want 1", seen)
	}
}

// TestLoadDedupesSpellingsOfTheSameFile guards the canonical key. `./a.mut`
// and `a.mut` are the same file; reaching it by two spellings must not produce
// two modules.
func TestLoadDedupesSpellingsOfTheSameFile(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut":  "import one \"a.mut\";\nimport two \"./sub/../a.mut\";\n",
		"a.mut":     "let a = 1;\n",
		"sub/dummy": "",
	})

	g, err := Load(filepath.Join(root, "main.mut"), nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if len(g.Modules) != 2 {
		t.Fatalf("expected 2 modules, got %d: %v", len(g.Modules), displayNames(g))
	}
}

func TestLoadReportsCycleAsTheChainThatClosedIt(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut": "import \"a.mut\";\n",
		"a.mut":    "import \"b.mut\";\n",
		"b.mut":    "import \"a.mut\";\n",
	})

	_, err := Load(filepath.Join(root, "main.mut"), nil)
	if err == nil {
		t.Fatal("expected a cycle error")
	}

	var cycle *CycleError
	if !errors.As(err, &cycle) {
		t.Fatalf("expected *CycleError, got %T: %v", err, err)
	}

	bases := make([]string, 0, len(cycle.Chain))
	for _, entry := range cycle.Chain {
		bases = append(bases, filepath.Base(entry))
	}
	got := strings.Join(bases, " -> ")
	want := "main.mut -> a.mut -> b.mut -> a.mut"
	if got != want {
		t.Fatalf("cycle chain = %q, want %q", got, want)
	}
	if !strings.Contains(err.Error(), "import cycle") {
		t.Fatalf("unhelpful cycle message: %s", err)
	}
}

func TestLoadReportsSelfImportAsACycle(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut": "import \"main.mut\";\n",
	})

	_, err := Load(filepath.Join(root, "main.mut"), nil)
	var cycle *CycleError
	if !errors.As(err, &cycle) {
		t.Fatalf("expected *CycleError, got %T: %v", err, err)
	}
	if len(cycle.Chain) != 2 {
		t.Fatalf("expected a two-entry chain for a self-import, got %v", cycle.Chain)
	}
}

// TestLoadMissingModuleNamesEveryDirectorySearched pins the message contract.
// The spelling alone is already in the reader's source; what decides whether
// the fix is a corrected path or another --module-path is where it looked.
func TestLoadMissingModuleNamesEveryDirectorySearched(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut": "import \"nope.mut\";\n",
	})
	libA := writeTree(t, map[string]string{"other.mut": ""})
	libB := writeTree(t, map[string]string{"other.mut": ""})

	_, err := Load(filepath.Join(root, "main.mut"), []string{libA, libB})
	if err == nil {
		t.Fatal("expected a not-found error")
	}

	var notFound *NotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("expected *NotFoundError, got %T: %v", err, err)
	}
	if len(notFound.Searched) != 3 {
		t.Fatalf("expected 3 candidates (importer dir + 2 search paths), got %v", notFound.Searched)
	}

	msg := err.Error()
	for _, dir := range []string{root, libA, libB} {
		if !strings.Contains(msg, dir) {
			t.Fatalf("message does not name %s:\n%s", dir, msg)
		}
	}
	if !strings.Contains(msg, "--module-path") {
		t.Fatalf("message does not say how to widen the search:\n%s", msg)
	}
	if !strings.Contains(msg, "main.mut") {
		t.Fatalf("message does not name the file that wrote the import:\n%s", msg)
	}
}

func TestLoadSearchesModulePathsInOrder(t *testing.T) {
	first := writeTree(t, map[string]string{"util.mut": "let which = 1;\n"})
	second := writeTree(t, map[string]string{"util.mut": "let which = 2;\n"})
	root := writeTree(t, map[string]string{"main.mut": "import \"util.mut\";\n"})

	g, err := Load(filepath.Join(root, "main.mut"), []string{first, second})
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	for _, mod := range g.Modules {
		if filepath.Base(mod.Path) != "util.mut" {
			continue
		}
		if !strings.HasPrefix(mod.Path, first) {
			t.Fatalf("resolved util.mut to %s, want the first --module-path %s", mod.Path, first)
		}
		return
	}
	t.Fatal("util.mut was not in the graph")
}

// TestLoadPrefersTheImporterOverSearchPaths pins the resolution order the
// policy decision settled on: relative to the importing file first, flags
// second.
func TestLoadPrefersTheImporterOverSearchPaths(t *testing.T) {
	lib := writeTree(t, map[string]string{"util.mut": "let which = 2;\n"})
	root := writeTree(t, map[string]string{
		"main.mut": "import \"util.mut\";\n",
		"util.mut": "let which = 1;\n",
	})

	g, err := Load(filepath.Join(root, "main.mut"), []string{lib})
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if !strings.HasPrefix(g.Modules[0].Path, root) {
		t.Fatalf("resolved util.mut to %s, want the importer's own directory %s", g.Modules[0].Path, root)
	}
}

func TestLoadResolvesRelativeToEachImporterNotTheEntry(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut":         "import \"lib/a.mut\";\n",
		"lib/a.mut":        "import \"nested/b.mut\";\n",
		"lib/nested/b.mut": "let b = 1;\n",
	})

	g, err := Load(filepath.Join(root, "main.mut"), nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(g.Modules) != 3 {
		t.Fatalf("expected 3 modules, got %v", displayNames(g))
	}
}

func TestLoadRejectsAPathWithoutTheExtension(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut": "import \"util\";\n",
		"util":     "let u = 1;\n",
	})

	_, err := Load(filepath.Join(root, "main.mut"), nil)
	var invalid *InvalidPathError
	if !errors.As(err, &invalid) {
		t.Fatalf("expected *InvalidPathError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), ".mut") {
		t.Fatalf("message does not say what the path must end in: %s", err)
	}
}

// TestLoadRejectsTwoImportsBindingOneName pins that a namespace collision is
// reported rather than resolved last-wins. Both files are named util.mut, so
// nothing in the source shows the clash.
func TestLoadRejectsTwoImportsBindingOneName(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut":   "import \"a/util.mut\";\nimport \"b/util.mut\";\n",
		"a/util.mut": "let a = 1;\n",
		"b/util.mut": "let b = 1;\n",
	})

	_, err := Load(filepath.Join(root, "main.mut"), nil)
	var dup *DuplicateNamespaceError
	if !errors.As(err, &dup) {
		t.Fatalf("expected *DuplicateNamespaceError, got %T: %v", err, err)
	}
	if dup.Namespace != "util" {
		t.Fatalf("collided on %q, want %q", dup.Namespace, "util")
	}
	if !strings.Contains(err.Error(), "alias") {
		t.Fatalf("message does not suggest the fix: %s", err)
	}
}

func TestLoadAllowsTheSameFileUnderTwoAliases(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut": "import one \"util.mut\";\nimport two \"util.mut\";\n",
		"util.mut": "let u = 1;\n",
	})

	g, err := Load(filepath.Join(root, "main.mut"), nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(g.Modules) != 2 {
		t.Fatalf("expected 2 modules, got %v", displayNames(g))
	}
	if len(g.Entry.Imports) != 2 {
		t.Fatalf("expected 2 resolved imports, got %d", len(g.Entry.Imports))
	}
	if g.Entry.Imports[0].Path != g.Entry.Imports[1].Path {
		t.Fatal("two aliases of one file must resolve to the same module")
	}
}

func TestLoadReportsAParseErrorAgainstTheOffendingModule(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut":   "import \"broken.mut\";\n",
		"broken.mut": "let = ;\n",
	})

	_, err := Load(filepath.Join(root, "main.mut"), nil)
	var parseErr *ParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected *ParseError, got %T: %v", err, err)
	}
	if filepath.Base(parseErr.Path) != "broken.mut" {
		t.Fatalf("parse error blamed %s, want broken.mut", parseErr.Path)
	}
}

func TestLoadReportsAnUnreadableEntry(t *testing.T) {
	root := t.TempDir()
	_, err := Load(filepath.Join(root, "absent.mut"), nil)
	var readErr *ReadError
	if !errors.As(err, &readErr) {
		t.Fatalf("expected *ReadError, got %T: %v", err, err)
	}
}

func TestLoadRecordsNamespacesAndSpellings(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut":      "import \"lib/util.mut\";\nimport helper \"lib/other.mut\";\n",
		"lib/util.mut":  "let u = 1;\n",
		"lib/other.mut": "let o = 1;\n",
	})

	g, err := Load(filepath.Join(root, "main.mut"), nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	imports := g.Entry.Imports
	if len(imports) != 2 {
		t.Fatalf("expected 2 imports, got %d", len(imports))
	}
	if imports[0].Namespace != "util" || imports[0].Spelling != "lib/util.mut" {
		t.Fatalf("unaliased import recorded as %+v", imports[0])
	}
	if imports[1].Namespace != "helper" || imports[1].Spelling != "lib/other.mut" {
		t.Fatalf("aliased import recorded as %+v", imports[1])
	}
	for _, imp := range imports {
		if imp.Statement == nil {
			t.Fatal("a resolved import must keep its statement for diagnostics")
		}
	}
}

func TestLoadKeepsSourceAndProgram(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut": "let x = 1;\n",
	})

	g, err := Load(filepath.Join(root, "main.mut"), nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if g.Entry.Source != "let x = 1;\n" {
		t.Fatalf("source not preserved verbatim: %q", g.Entry.Source)
	}
	if g.Entry.Program == nil || len(g.Entry.Program.Statements) != 1 {
		t.Fatal("the parsed program must be kept for linking")
	}
}

func TestResolveRejectsADirectory(t *testing.T) {
	root := writeTree(t, map[string]string{"pkg.mut/keep": ""})

	_, err := NewResolver(nil).Resolve("pkg.mut", root)
	if err == nil {
		t.Fatal("a directory named like a module must not satisfy an import")
	}
}
