package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/lsp/internal/analyzer"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// The language server has never known what an import means. It did not import
// mutant/module at all, so `stats.mean` had no code path: no completion, no
// definition, no hover, while the compiler resolved it exactly.
//
// These tests drive the real server -- a disk scan, then an opened document --
// rather than an analyzer built by hand, because the wiring is most of what
// was missing. An analyzer that could answer and a server that never asked it
// would pass a unit test and ship the same bug.

// writeModules materialises a tree and returns its root.
func writeModules(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, src := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// serverOver scans root the way initialize does, then opens one file the way an
// editor does, and returns the server plus that document's URI.
func serverOver(t *testing.T, root, openRel string) (*Server, lsp.DocumentUri) {
	t.Helper()
	s := New(false)
	s.setRoots([]string{root})
	s.scanWorkspace()

	path := filepath.Join(root, openRel)
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	uri := pathToURI(path)
	s.documents.Open(uri, 1, string(source))
	s.evictScannedEntryFor(uri)
	snapshot := s.analyzeDoc(uri, string(source))
	s.setSnapshot(uri, snapshot)
	return s, uri
}

var memberFixture = map[string]string{
	"main.mut": "import stats \"lib/stats.mut\";\n" +
		"let label = \"main\";\n" +
		"let main = fn() {\n" +
		"\tstats.\n" +
		"};\n",
	"lib/stats.mut": "let _total = fn(xs) { return 1; };\n" +
		"let mean = fn(xs) { return _total(xs); };\n" +
		"let limit = 10;\n",
	"other/spare.mut": "let orphan = fn() { return 1; };\n",
}

// The cursor sits just after `stats.` on line 3 (0-based), column 7.
var afterStatsDot = lsp.Position{Line: 3, Character: 7}

func TestNamespaceDotOffersTheImportedModulesExports(t *testing.T) {
	s, uri := serverOver(t, writeModules(t, memberFixture), "main.mut")

	snapshot, ok := s.snapshot(uri)
	if !ok {
		t.Fatal("the opened document has no snapshot")
	}
	items, ok := snapshot.MemberCompletionsAt(afterStatsDot)
	if !ok {
		t.Fatal("`stats.` offered nothing -- the editor still does not know what the import names")
	}

	offered := make(map[string]lsp.CompletionItemKind, len(items))
	for _, item := range items {
		if item.Kind == nil {
			t.Fatalf("%q was offered with no kind", item.Label)
		}
		offered[item.Label] = *item.Kind
	}

	if kind, found := offered["mean"]; !found {
		t.Fatalf("`stats.` did not offer mean; offered %v", offered)
	} else if kind != lsp.CompletionItemKindFunction {
		t.Fatalf("mean was offered as kind %v, want Function", kind)
	}
	if kind, found := offered["limit"]; !found {
		t.Fatalf("`stats.` did not offer limit; offered %v", offered)
	} else if kind != lsp.CompletionItemKindVariable {
		t.Fatalf("limit was offered as kind %v, want Variable", kind)
	}

	// The whole export rule, applied where the user can see it. Offering
	// _total would be offering a name the build refuses.
	if _, found := offered["_total"]; found {
		t.Fatal("`stats.` offered a module-private name")
	}

	// And nothing from a module this file never imported.
	if _, found := offered["orphan"]; found {
		t.Fatal("`stats.` offered a member of a module nothing imported")
	}
}

// A namespace whose target has not been scanned must offer nothing at all.
// An empty list is a claim that the module declares nothing, which is a
// different and wrong statement.
func TestNamespaceDotOffersNothingForAnUnscannedModule(t *testing.T) {
	root := writeModules(t, map[string]string{
		"main.mut": memberFixture["main.mut"],
	})
	s, uri := serverOver(t, root, "main.mut")

	snapshot, _ := s.snapshot(uri)
	items, ok := snapshot.MemberCompletionsAt(afterStatsDot)
	if ok || len(items) != 0 {
		t.Fatalf("an unscanned module offered %d completions", len(items))
	}
}

// Analyze(src) keeps working with no workspace at all -- that is what api.Lint,
// the REPL and about 99 tests use. It must simply decline the cross-file
// question rather than guess at it.
func TestAnalyzeWithoutAWorkspaceStillWorksAndDeclines(t *testing.T) {
	snapshot := New(false).analyzer.Analyze(memberFixture["main.mut"])
	if snapshot == nil || snapshot.Program == nil {
		t.Fatal("Analyze(src) stopped producing a usable snapshot")
	}
	if items, ok := snapshot.MemberCompletionsAt(afterStatsDot); ok || len(items) != 0 {
		t.Fatalf("a workspace-less snapshot offered %d cross-file completions", len(items))
	}
}

// A file the editor opens must beat the copy the disk scan read, or an edit
// would resolve against the version on disk.
func TestAnOpenDocumentsExportsReplaceTheScannedOnes(t *testing.T) {
	root := writeModules(t, memberFixture)
	s, _ := serverOver(t, root, "main.mut")

	libPath := filepath.Join(root, "lib", "stats.mut")
	libURI := pathToURI(libPath)

	// The editor opens stats.mut and adds an export without saving.
	edited := "let _total = fn(xs) { return 1; };\n" +
		"let mean = fn(xs) { return _total(xs); };\n" +
		"let limit = 10;\n" +
		"let median = fn(xs) { return 2; };\n"
	s.documents.Open(libURI, 1, edited)
	s.evictScannedEntryFor(libURI)
	s.setSnapshot(libURI, s.analyzeDoc(libURI, edited))

	mainURI := pathToURI(filepath.Join(root, "main.mut"))
	snapshot, _ := s.snapshot(mainURI)
	items, ok := snapshot.MemberCompletionsAt(afterStatsDot)
	if !ok {
		t.Fatal("`stats.` offered nothing after the target was opened")
	}
	for _, item := range items {
		if item.Label == "median" {
			return
		}
	}
	t.Fatalf("an unsaved export did not reach the importer; offered %v", items)
}

// Cross-file go-to-definition, which had no code path at all.
func TestGoToDefinitionFollowsAnImportIntoTheOtherFile(t *testing.T) {
	root := writeModules(t, map[string]string{
		"main.mut": "import stats \"lib/stats.mut\";\n" +
			"let main = fn() { return stats.mean([1]); };\n",
		"lib/stats.mut": "let _total = fn(xs) { return 1; };\n" +
			"let mean = fn(xs) { return _total(xs); };\n",
	})
	s, uri := serverOver(t, root, "main.mut")
	snapshot, _ := s.snapshot(uri)

	// The cursor on `mean` in `stats.mean` on line 1.
	onMean := lsp.Position{Line: 1, Character: 31}
	location, ok := snapshot.ModuleMemberDefinition(onMean)
	if !ok {
		t.Fatal("stats.mean has no definition -- the editor still cannot follow an import")
	}

	landed, isFile := uriToPath(location.URI)
	if !isFile {
		t.Fatalf("definition returned a URI that is not a file: %q", location.URI)
	}
	if want := filepath.Join(root, "lib", "stats.mut"); canonicalPath(landed) != canonicalPath(want) {
		t.Fatalf("jumped to %s, want %s", landed, want)
	}
	// `mean` is declared on the second line of stats.mut.
	if location.Range.Start.Line != 1 {
		t.Fatalf("jumped to line %d, want line 1 (0-based)", location.Range.Start.Line)
	}
}

// A module nothing imported must not be a jump target, however well its names
// match. This is the bug in the current name-matching index.
//
// The same source line is asked about twice, at the same position, differing
// only in whether the import is there. Without that second half the test would
// still pass if the position simply landed on nothing at all.
func TestGoToDefinitionDoesNotJumpIntoAnUnimportedModule(t *testing.T) {
	// `orphan` begins at character 31 of this line, in both fixtures.
	const body = "let main = fn() { return spare.orphan(); };\n"
	const spare = "let orphan = fn() { return 1; };\n"
	onOrphan := lsp.Position{Line: 1, Character: 32}

	withoutImport := writeModules(t, map[string]string{
		"main.mut":        "let unrelated = 1;\n" + body,
		"other/spare.mut": spare,
	})
	s, uri := serverOver(t, withoutImport, "main.mut")
	snapshot, _ := s.snapshot(uri)
	if location, ok := snapshot.ModuleMemberDefinition(onOrphan); ok {
		t.Fatalf("jumped into %q, which main.mut never imported", location.URI)
	}

	// The same position and the same expression, now imported: it must resolve.
	// That is what makes the refusal above meaningful rather than a miss.
	withImport := writeModules(t, map[string]string{
		"main.mut":        "import spare \"other/spare.mut\";\n" + body,
		"other/spare.mut": spare,
	})
	s2, uri2 := serverOver(t, withImport, "main.mut")
	snapshot2, _ := s2.snapshot(uri2)
	if _, ok := snapshot2.ModuleMemberDefinition(onOrphan); !ok {
		t.Fatal("the position does not name a module member even when imported, so the negative case proves nothing")
	}
}

// The compiler's exact sentence, as a squiggle.
func TestAPrivateReachIsDiagnosedWithTheCompilersSentence(t *testing.T) {
	root := writeModules(t, map[string]string{
		"main.mut": "import util \"lib/util.mut\";\n" +
			"let main = fn() { return util._secret(); };\n",
		"lib/util.mut": "let _secret = fn() { return 1; };\n",
	})
	s, uri := serverOver(t, root, "main.mut")
	snapshot, _ := s.snapshot(uri)

	diags := snapshot.ModuleMemberDiagnostics()
	if len(diags) != 1 {
		t.Fatalf("got %d diagnostics, want exactly one: %v", len(diags), diags)
	}
	want := "util._secret is private to " + filepath.Join(root, "lib", "util.mut") +
		": a top-level name beginning with _ is visible only inside the module that declares it"
	if diags[0].Message != want {
		t.Fatalf("message:\n got %q\nwant %q", diags[0].Message, want)
	}
	if diags[0].Range.Start.Line != 1 {
		t.Fatalf("squiggle on line %d, want line 1", diags[0].Range.Start.Line)
	}

	// And it reaches the published set, not just this one method.
	published := analyzer.Diagnostics(snapshot, s.currentLintConfig())
	for _, d := range published {
		if d.Message == want {
			return
		}
	}
	t.Fatal("the refusal never reached the published diagnostics")
}

// A legal program produces no module diagnostics, and neither does one whose
// imports have not been read: "declares no such name" about an unread file is a
// refusal invented out of ignorance.
func TestNoModuleDiagnosticsForLegalOrUnreadCode(t *testing.T) {
	legal := writeModules(t, map[string]string{
		"main.mut":      "import stats \"lib/stats.mut\";\nlet main = fn() { return stats.mean([1]); };\n",
		"lib/stats.mut": "let mean = fn(xs) { return 1; };\n",
	})
	s, uri := serverOver(t, legal, "main.mut")
	snapshot, _ := s.snapshot(uri)
	if diags := snapshot.ModuleMemberDiagnostics(); len(diags) != 0 {
		t.Fatalf("a legal program was diagnosed: %v", diags)
	}

	unread := writeModules(t, map[string]string{
		"main.mut": "import stats \"lib/stats.mut\";\nlet main = fn() { return stats.nosuch([1]); };\n",
	})
	s2, uri2 := serverOver(t, unread, "main.mut")
	snapshot2, _ := s2.snapshot(uri2)
	if diags := snapshot2.ModuleMemberDiagnostics(); len(diags) != 0 {
		t.Fatalf("an unread module was diagnosed: %v", diags)
	}
}

// Hover across a module boundary. The declaration is in another file, which is
// exactly why the reader needs to be told about it.
func TestHoverDescribesADeclarationInAnotherFile(t *testing.T) {
	root := writeModules(t, map[string]string{
		"main.mut":      "import stats \"lib/stats.mut\";\nlet main = fn() { return stats.mean([1]); };\n",
		"lib/stats.mut": "let mean = fn(xs, weight) { return 1; };\nlet limit = 10;\n",
	})
	s, uri := serverOver(t, root, "main.mut")
	snapshot, _ := s.snapshot(uri)

	text, _, ok := snapshot.ModuleMemberHover(lsp.Position{Line: 1, Character: 31})
	if !ok {
		t.Fatal("no hover for stats.mean")
	}
	// The signature, with the parameter names the other file actually wrote.
	if !strings.Contains(text, "mean(xs, weight)") {
		t.Fatalf("hover does not show the signature:\n%s", text)
	}
	// And which file it came from, which is the thing the reader cannot see.
	if !strings.Contains(text, filepath.Join(root, "lib", "stats.mut")) {
		t.Fatalf("hover does not name the declaring module:\n%s", text)
	}
	// No invented types: Mutant has no parameter annotations.
	for _, invented := range []string{"int", "array", "string", "any"} {
		if strings.Contains(text, invented) {
			t.Fatalf("hover invented a type %q:\n%s", invented, text)
		}
	}
}

// A module the workspace has not read must produce no hover at all, rather
// than a card describing a guess.
func TestHoverSaysNothingAboutAnUnreadModule(t *testing.T) {
	root := writeModules(t, map[string]string{
		"main.mut": "import stats \"lib/stats.mut\";\nlet main = fn() { return stats.mean([1]); };\n",
	})
	s, uri := serverOver(t, root, "main.mut")
	snapshot, _ := s.snapshot(uri)

	if text, _, ok := snapshot.ModuleMemberHover(lsp.Position{Line: 1, Character: 31}); ok {
		t.Fatalf("hovered an unread module: %s", text)
	}
}

// Through the handler, not the method, so the order the two hover sources are
// tried in is actually exercised. The file-local walk sees `mean` as a bare
// identifier and has something to say about it; if it ran first, the reader
// would be told about that instead of about the declaration in the other file.
func TestTheHoverHandlerPrefersTheCrossModuleAnswer(t *testing.T) {
	root := writeModules(t, map[string]string{
		"main.mut":      "import stats \"lib/stats.mut\";\nlet main = fn() { return stats.mean([1]); };\n",
		"lib/stats.mut": "let mean = fn(xs, weight) { return 1; };\n",
	})
	s, uri := serverOver(t, root, "main.mut")

	result, err := s.hover(nil, &lsp.HoverParams{
		TextDocumentPositionParams: lsp.TextDocumentPositionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: uri},
			Position:     lsp.Position{Line: 1, Character: 31},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("the hover handler returned nothing for stats.mean")
	}
	content, ok := result.Contents.(lsp.MarkupContent)
	if !ok {
		t.Fatalf("hover contents are %T, want MarkupContent", result.Contents)
	}
	if !strings.Contains(content.Value, "mean(xs, weight)") {
		t.Fatalf("the handler did not serve the cross-module card:\n%s", content.Value)
	}
	if !strings.Contains(content.Value, filepath.Join(root, "lib", "stats.mut")) {
		t.Fatalf("the handler did not name the declaring module:\n%s", content.Value)
	}
}

// Through the definition handler, so the order of its three sources is
// exercised. The last of them resolves a bare name by matching it against every
// indexed document, which is what makes go-to-definition jump into modules
// nothing imported. Here two files declare `mean`, only one is imported, and
// the import has to win.
func TestTheDefinitionHandlerPrefersTheImportedModule(t *testing.T) {
	root := writeModules(t, map[string]string{
		"main.mut":        "import stats \"lib/stats.mut\";\nlet main = fn() { return stats.mean([1]); };\n",
		"lib/stats.mut":   "let mean = fn(xs) { return 1; };\n",
		"other/decoy.mut": "let mean = fn(xs) { return 99; };\n",
	})
	s, uri := serverOver(t, root, "main.mut")

	result, err := s.definition(nil, &lsp.DefinitionParams{
		TextDocumentPositionParams: lsp.TextDocumentPositionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: uri},
			Position:     lsp.Position{Line: 1, Character: 31},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Both shapes are accepted here on purpose: the fallback that produces the
	// bug returns a *Location, and refusing to look at it would turn this into
	// a test about return types rather than about where the jump lands.
	var target lsp.DocumentUri
	switch location := result.(type) {
	case lsp.Location:
		target = location.URI
	case *lsp.Location:
		target = location.URI
	default:
		t.Fatalf("definition returned %T, want a Location", result)
	}

	landed, ok := uriToPath(target)
	if !ok {
		t.Fatalf("definition returned a URI that is not a file: %q", target)
	}
	got := canonicalPath(landed)

	if want := canonicalPath(filepath.Join(root, "lib", "stats.mut")); got != want {
		t.Fatalf("jumped to %s, want the imported module %s", got, want)
	}
	if decoy := canonicalPath(filepath.Join(root, "other", "decoy.mut")); got == decoy {
		t.Fatal("jumped into the module that merely declares a matching name")
	}
}
