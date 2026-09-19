package server

import (
	"strings"
	"testing"

	"mutant/lsp/internal/analyzer"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// The same questions as parity/macro_parity_test.go, asked through the server's
// own workspace scan rather than through api.NewProject.
//
// It is worth asking twice. The parity test proves the rule is right; this
// proves the editor is the thing holding it, over a workspace that was scanned
// from disk with only one file open -- which is the arrangement a user is
// actually in.

func allDiagnostics(t *testing.T, root, openRel string) []string {
	t.Helper()
	s, uri := serverOver(t, root, openRel)
	snapshot, ok := s.snapshot(uri)
	if !ok {
		t.Fatalf("%s has no snapshot", openRel)
	}
	said := make([]string, 0, 4)
	for _, d := range analyzer.Diagnostics(snapshot, analyzer.DefaultLintConfig()) {
		said = append(said, d.Message)
	}
	return said
}

var crossModuleLibrary = map[string]string{
	"alpha.mut": "let twice = macro(x) {\n\tquote(unquote(x) + unquote(x));\n};\n" +
		"struct Point { x }\n" +
		"enum Colour { Red }\n",
}

func fixtureWith(main string) map[string]string {
	files := map[string]string{"main.mut": main}
	for name, src := range crossModuleLibrary {
		files[name] = src
	}
	return files
}

// Four diagnostics on a four-line program that compiles and runs. Three of the
// four predate the symbol graph; the fourth arrived with the unused-import
// rule, which could not see that an import brings more than its alias.
func TestAFileUsingOnlyBareCrossModuleNamesDrawsNothing(t *testing.T) {
	root := writeModules(t, fixtureWith(
		"import a \"alpha.mut\";\n"+
			"let p = Point{x: 1};\n"+
			"let c = Colour.Red;\n"+
			"let n = twice(21);\n"+
			"[p, c, n];\n"))

	if said := allDiagnostics(t, root, "main.mut"); len(said) != 0 {
		t.Fatalf("the editor drew %v on a program the compiler accepts", said)
	}
}

// The whitelist is a whitelist. An import that brings nothing this file uses is
// still an unused import, and a name nothing declares is still undefined.
func TestAnImportBringingNothingUsedIsStillUnused(t *testing.T) {
	root := writeModules(t, fixtureWith(
		"import a \"alpha.mut\";\n"+
			"let bad = nope.f();\n"+
			"let worse = notAThing;\n"+
			"[bad, worse];\n"))

	said := allDiagnostics(t, root, "main.mut")
	for _, want := range []string{"unused import", "nope", "notAThing"} {
		found := false
		for _, message := range said {
			if strings.Contains(message, want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("%q was not reported. The rules must go quiet because an "+
				"import supplies the name, not because the file contains an "+
				"import. said = %v", want, said)
		}
	}
}

// One import of two is load-bearing. The other is not, and saying so is the
// whole value of the rule.
func TestOnlyTheImportThatSuppliesTheNameIsSpared(t *testing.T) {
	files := fixtureWith(
		"import a \"alpha.mut\";\n" +
			"import s \"spare.mut\";\n" +
			"let p = Point{x: 1};\n" +
			"p;\n")
	files["spare.mut"] = "let unrelated = fn() { return 1; };\n"
	root := writeModules(t, files)

	said := allDiagnostics(t, root, "main.mut")
	unused := make([]string, 0, 2)
	for _, message := range said {
		if strings.Contains(message, "unused import") {
			unused = append(unused, message)
		}
	}
	if len(unused) != 1 {
		t.Fatalf("expected exactly one unused import, got %v (all: %v)", unused, said)
	}
	if !strings.Contains(unused[0], "`s`") {
		t.Fatalf("the wrong import was called unused: %s -- `a` is what brings Point", unused[0])
	}
}

// A macro is not offered behind the dot, because `a.twice` does not compile.
func TestNamespaceDotDoesNotOfferAMacro(t *testing.T) {
	root := writeModules(t, fixtureWith(
		"import a \"alpha.mut\";\n"+
			"let main = fn() {\n"+
			"\ta.\n"+
			"};\n"))
	s, uri := serverOver(t, root, "main.mut")
	snapshot, ok := s.snapshot(uri)
	if !ok {
		t.Fatal("no snapshot")
	}

	items, offered := snapshot.MemberCompletionsAt(lsp.Position{Line: 2, Character: 3})
	if !offered {
		return // nothing offered at all is not this test's concern
	}
	for _, item := range items {
		if item.Label == "twice" {
			t.Fatal("`a.` offered a macro. The compiler refuses that spelling: " +
				"the declaration is deleted before the module's scope is built")
		}
	}
}

// A macro call is written bare, so it is the type-name path that has to find it
// -- the namespace path refuses `a.twice` and is right to.
func TestGoToDefinitionFollowsABareMacroIntoTheModuleThatDeclaresIt(t *testing.T) {
	root := writeModules(t, map[string]string{
		"lib.mut":  "let twice = macro(x) {\n\tquote(unquote(x) + unquote(x));\n};\n",
		"main.mut": "import a \"lib.mut\";\nlet n = twice(21);\nn;\n",
	})
	s, uri := serverOver(t, root, "main.mut")

	result, err := s.definition(nil, &lsp.DefinitionParams{
		TextDocumentPositionParams: lsp.TextDocumentPositionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: uri},
			// `let n = twice(21);` -- twice begins at character 8.
			Position: lsp.Position{Line: 1, Character: 9},
		},
	})
	if err != nil {
		t.Fatalf("definition returned error: %v", err)
	}
	location, ok := result.(*lsp.Location)
	if !ok || location == nil {
		t.Fatalf("definition result type = %T, want *Location -- a macro call had "+
			"nowhere to go, because a macro was filed as a thing reached through "+
			"a namespace and the namespace path refuses it", result)
	}
	if want := pathToURI(root + "/lib.mut"); location.URI != want {
		t.Fatalf("definition URI = %q, want %q", location.URI, want)
	}
	// `let twice = macro(...)` -- the name begins at character 4.
	if location.Range.Start.Line != 0 || location.Range.Start.Character != 4 {
		t.Fatalf("definition start = %+v, want line 0 char 4", location.Range.Start)
	}
}

// And the uses, in every file that reaches the module -- under no alias at all,
// because there is no alias to write.
func TestReferencesToAMacroSpanTheFilesThatImportIt(t *testing.T) {
	root := writeModules(t, map[string]string{
		"lib.mut":   "let twice = macro(x) {\n\tquote(unquote(x) + unquote(x));\n};\n",
		"main.mut":  "import a \"lib.mut\";\nlet n = twice(1);\nn;\n",
		"other.mut": "import b \"lib.mut\";\nlet p = twice(2);\nlet q = twice(3);\n[p, q];\n",
		"stray.mut": "let twice = macro(x) {\n\tquote(unquote(x));\n};\nlet r = twice(4);\nr;\n",
	})
	s, uri := serverOver(t, root, "main.mut")

	result, err := s.references(nil, &lsp.ReferenceParams{
		TextDocumentPositionParams: lsp.TextDocumentPositionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: uri},
			Position:     lsp.Position{Line: 1, Character: 9},
		},
		Context: lsp.ReferenceContext{IncludeDeclaration: false},
	})
	if err != nil {
		t.Fatalf("references returned error: %v", err)
	}

	byURI := map[lsp.DocumentUri]int{}
	for _, location := range result {
		byURI[location.URI]++
	}
	if got := byURI[pathToURI(root+"/other.mut")]; got != 2 {
		t.Fatalf("references in other.mut = %d, want 2 -- it imports lib.mut and "+
			"calls the macro twice: %+v", got, result)
	}
	if got := byURI[pathToURI(root+"/stray.mut")]; got != 0 {
		t.Fatalf("references in stray.mut = %d, want 0: it declares a macro of its "+
			"own name and imports nothing", got)
	}
}
