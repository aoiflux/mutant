package workspace

import (
	"path/filepath"
	"testing"

	mast "mutant/ast"
	"mutant/lexer"
	"mutant/lsp/internal/analyzer"
	"mutant/parser"
	"mutant/sema"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// These tests used to say the opposite of what they say now.
//
// They asserted that `let shared = 1;` in one file and `shared;` in another --
// two files with no import between them, in no particular directory, never
// compiled together -- resolved to each other. That was the contract the index
// was written to, and it was wrong: an import binds one namespace, and a name
// declared in another file is not in this file's scope because it is spelled
// the same.
//
// What is asserted instead is the narrow thing that is true, and each negative
// is paired with a positive so that a refusal means "the rule held" rather than
// "the fixture was wired up wrong".

// indexed builds an index and a workspace over the same set of files, keyed the
// way the server keys them. The paths are under a directory that does not exist:
// nothing here reads a disk.
func indexed(t *testing.T, files map[string]string) (*SymbolIndex, *sema.Workspace, func(string) lsp.DocumentUri) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "proj")

	idx := NewSymbolIndex()
	w := sema.NewWorkspace(nil)
	uriOf := func(rel string) lsp.DocumentUri {
		return lsp.DocumentUri("file:///" + filepath.ToSlash(filepath.Join(root, rel)))
	}

	for rel, src := range files {
		path := filepath.Join(root, rel)
		uri := uriOf(rel)

		p := parser.New(lexer.New(src))
		program := p.ParseProgram()
		if errs := p.Errors(); len(errs) > 0 {
			t.Fatalf("fixture %s did not parse: %v", rel, errs)
		}
		w.PutFile(string(uri), path, program)
		idx.Update(uri, analyzedSnapshot(t, src))
	}
	return idx, w, uriOf
}

func keyOf(t *testing.T, w *sema.Workspace, uri lsp.DocumentUri) string {
	t.Helper()
	key, ok := w.KeyForURI(string(uri))
	if !ok {
		t.Fatalf("no module key for %s", uri)
	}
	return key
}

// A value is reached through the namespace that imports it, and every use is
// written that way. This is the case the old index could not see at all.
func TestAValuesUsesAreTheOnesWrittenThroughAnImportedNamespace(t *testing.T) {
	idx, w, uriOf := indexed(t, map[string]string{
		"lib.mut": "let mean = fn(xs) { return 0; };\n",
		"main.mut": "import stats \"lib.mut\";\n" +
			"let a = stats.mean([1]);\n" +
			"let b = stats.mean([2]);\n",
	})

	locations := idx.ReferencesTo(w, keyOf(t, w, uriOf("lib.mut")), "mean", false, nil, false)
	if len(locations) != 2 {
		t.Fatalf("reference count = %d, want 2: %+v", len(locations), locations)
	}
	for _, location := range locations {
		if location.URI != uriOf("main.mut") {
			t.Fatalf("reference in %s, want main.mut", location.URI)
		}
		// The range covers `mean` alone. Renaming must not eat the `stats.`
		// in front of it.
		// `let a = stats.mean(...)`: `stats` is at 8, `mean` at 14.
		if location.Range.Start.Character != 14 || location.Range.End.Character != 18 {
			t.Fatalf("reference covers characters %d-%d, want 14-18: the member "+
				"name alone, not the whole expression",
				location.Range.Start.Character, location.Range.End.Character)
		}
	}
}

// The bug, stated as a test: a name that matches and a file that never imported
// it. The same program with the import added proves the fixture is sound.
func TestAMatchingNameInAFileThatImportsNothingIsNotAReference(t *testing.T) {
	const lib = "let mean = fn(xs) { return 0; };\n"
	const use = "let a = stats.mean([1]);\n"

	withoutImport, w, uriOf := indexed(t, map[string]string{
		"lib.mut":  lib,
		"main.mut": use,
	})
	if locations := withoutImport.ReferencesTo(w, keyOf(t, w, uriOf("lib.mut")), "mean", false, nil, false); len(locations) != 0 {
		t.Fatalf("found %d references from a file that imports nothing: %+v",
			len(locations), locations)
	}

	withImport, w2, uriOf2 := indexed(t, map[string]string{
		"lib.mut":  lib,
		"main.mut": "import stats \"lib.mut\";\n" + use,
	})
	if locations := withImport.ReferencesTo(w2, keyOf(t, w2, uriOf2("lib.mut")), "mean", false, nil, false); len(locations) != 1 {
		t.Fatalf("the same use is not found even with the import, so the refusal "+
			"above proves nothing: got %d references", len(locations))
	}
}

// A file can import one module twice. Both spellings are real uses, and a
// rename that changed only the first would leave the program broken.
func TestBothAliasesOfATwiceImportedModuleCount(t *testing.T) {
	idx, w, uriOf := indexed(t, map[string]string{
		"lib.mut": "let mean = fn(xs) { return 0; };\n",
		"main.mut": "import first \"lib.mut\";\n" +
			"import second \"lib.mut\";\n" +
			"let a = first.mean([1]);\n" +
			"let b = second.mean([2]);\n",
	})

	if locations := idx.ReferencesTo(w, keyOf(t, w, uriOf("lib.mut")), "mean", false, nil, false); len(locations) != 2 {
		t.Fatalf("reference count = %d, want 2: %+v", len(locations), locations)
	}
}

// A struct name is program-global, so it is written bare -- the one kind of
// declaration another file names without a namespace in front of it.
func TestATypesUsesAreTheOnesWrittenBareInFilesThatReachIt(t *testing.T) {
	idx, w, uriOf := indexed(t, map[string]string{
		"lib.mut": "struct Point { x, y };\n",
		"main.mut": "import lib \"lib.mut\";\n" +
			"let p = Point{x: 1, y: 2};\n",
		"stray.mut": "let q = Point{x: 9, y: 9};\n",
	})

	locations := idx.ReferencesTo(w, keyOf(t, w, uriOf("lib.mut")), "Point", true, nil, false)
	if len(locations) != 1 {
		t.Fatalf("reference count = %d, want 1 -- stray.mut imports nothing: %+v",
			len(locations), locations)
	}
	if locations[0].URI != uriOf("main.mut") {
		t.Fatalf("reference in %s, want main.mut", locations[0].URI)
	}
}

// A namespaced member is not a bare name. `stats.mean` must not count as a use
// of some unrelated top-level `mean`, or a rename would reach into the middle
// of a call it has nothing to do with.
func TestAMemberNameIsNotABareUseOfTheSameSpelling(t *testing.T) {
	idx, w, uriOf := indexed(t, map[string]string{
		"types.mut": "struct mean { x };\n",
		"main.mut": "import types \"types.mut\";\n" +
			"import stats \"stats.mut\";\n" +
			"let a = stats.mean([1]);\n",
		"stats.mut": "let mean = fn(xs) { return 0; };\n",
	})

	if locations := idx.ReferencesTo(w, keyOf(t, w, uriOf("types.mut")), "mean", true, nil, false); len(locations) != 0 {
		t.Fatalf("the `mean` in `stats.mean` was counted as a bare use of the "+
			"struct: %+v", locations)
	}
}

// A file that declares the name itself is talking about its own. `let Point = 1`
// and `struct Point` can coexist -- claimTypeName governs types and the symbol
// table governs values -- so a bare `Point` in that file may be either, and this
// cannot tell which. It skips the file rather than guess: a find-references that
// misses a use is a smaller wrong than a rename that rewrites the wrong one.
func TestAFileThatDeclaresTheNameItselfIsLeftAlone(t *testing.T) {
	idx, w, uriOf := indexed(t, map[string]string{
		"lib.mut": "struct Point { x, y };\n",
		"main.mut": "import lib \"lib.mut\";\n" +
			"let Point = 1;\n" +
			"let n = Point;\n",
		"clean.mut": "import lib \"lib.mut\";\n" +
			"let p = Point{x: 1, y: 2};\n",
	})

	locations := idx.ReferencesTo(w, keyOf(t, w, uriOf("lib.mut")), "Point", true, nil, false)
	for _, location := range locations {
		if location.URI == uriOf("main.mut") {
			t.Fatalf("a use in main.mut was reported, but main.mut declares its own "+
				"Point: %+v", locations)
		}
	}
	// clean.mut declares nothing of the sort, so its use must still be found --
	// otherwise the refusal above would be indistinguishable from the whole
	// query returning nothing.
	if len(locations) != 1 || locations[0].URI != uriOf("clean.mut") {
		t.Fatalf("references = %+v, want exactly the use in clean.mut", locations)
	}
}

func TestTheDeclarationIsIncludedOnlyWhenAskedFor(t *testing.T) {
	idx, w, uriOf := indexed(t, map[string]string{
		"lib.mut": "let mean = fn(xs) { return 0; };\n",
		"main.mut": "import stats \"lib.mut\";\n" +
			"let a = stats.mean([1]);\n",
	})
	declaration := &lsp.Location{
		URI:   uriOf("lib.mut"),
		Range: lsp.Range{Start: lsp.Position{Line: 0, Character: 4}, End: lsp.Position{Line: 0, Character: 8}},
	}
	key := keyOf(t, w, uriOf("lib.mut"))

	if got := len(idx.ReferencesTo(w, key, "mean", false, declaration, true)); got != 2 {
		t.Fatalf("reference count with declaration = %d, want 2", got)
	}
	if got := len(idx.ReferencesTo(w, key, "mean", false, declaration, false)); got != 1 {
		t.Fatalf("reference count without declaration = %d, want 1", got)
	}
}

func TestDeleteRemovesADocumentsUses(t *testing.T) {
	idx, w, uriOf := indexed(t, map[string]string{
		"lib.mut": "let mean = fn(xs) { return 0; };\n",
		"main.mut": "import stats \"lib.mut\";\n" +
			"let a = stats.mean([1]);\n",
	})
	key := keyOf(t, w, uriOf("lib.mut"))

	if got := len(idx.ReferencesTo(w, key, "mean", false, nil, false)); got != 1 {
		t.Fatalf("reference count before delete = %d, want 1", got)
	}
	idx.Delete(uriOf("main.mut"))
	if got := len(idx.ReferencesTo(w, key, "mean", false, nil, false)); got != 0 {
		t.Fatalf("reference count after delete = %d, want 0", got)
	}
}

func TestUpdateReplacesADocumentsUsesRatherThanAddingToThem(t *testing.T) {
	idx, w, uriOf := indexed(t, map[string]string{
		"lib.mut": "let mean = fn(xs) { return 0; };\n",
		"main.mut": "import stats \"lib.mut\";\n" +
			"let a = stats.mean([1]);\n" +
			"let b = stats.mean([2]);\n",
	})
	key := keyOf(t, w, uriOf("lib.mut"))

	if got := len(idx.ReferencesTo(w, key, "mean", false, nil, false)); got != 2 {
		t.Fatalf("initial reference count = %d, want 2", got)
	}

	idx.Update(uriOf("main.mut"), analyzedSnapshot(t,
		"import stats \"lib.mut\";\nlet a = stats.mean([1]);\n"))
	if got := len(idx.ReferencesTo(w, key, "mean", false, nil, false)); got != 1 {
		t.Fatalf("reference count after update = %d, want 1", got)
	}
}

// The index reports TopLevelKind so a caller can tell a struct from a value
// without walking the document a second time. Getting it wrong would make a
// value's uses be looked for bare, which is the old bug in miniature.
func TestTopLevelKindDistinguishesATypeFromAValue(t *testing.T) {
	idx, _, uriOf := indexed(t, map[string]string{
		"defs.mut": "let value = 1;\nstruct Shape { n };\nenum Colour { Red };\n",
	})

	for name, wantType := range map[string]bool{"value": false, "Shape": true, "Colour": true} {
		kind, known := idx.TopLevelKind(uriOf("defs.mut"), name)
		if !known {
			t.Fatalf("%s is not reported as a top-level symbol", name)
		}
		if IsTypeKind(kind) != wantType {
			t.Fatalf("IsTypeKind(%s) = %v, want %v", name, IsTypeKind(kind), wantType)
		}
	}
	if _, known := idx.TopLevelKind(uriOf("defs.mut"), "absent"); known {
		t.Fatal("a name the document does not declare was reported as top level")
	}
}

// Update walks a whole parsed program, and a parser mid-keystroke produces
// partial nodes. A typed nil inside an interface is not caught by == nil, and
// these two shapes have crashed this walk before.
func TestUpdateSurvivesATypedNilStatement(t *testing.T) {
	idx := NewSymbolIndex()
	var typedNilInit *mast.ExpressionStatement

	idx.Update("file:///typed-nil-stmt.mut", &analyzer.Snapshot{
		Program: &mast.Program{
			Statements:    []mast.Statement{&mast.ForStatement{Init: typedNilInit}},
			NodePositions: map[mast.Node]mast.Range{},
		},
	})
}

func TestUpdateSurvivesATypedNilExpression(t *testing.T) {
	idx := NewSymbolIndex()
	var typedNilCondition *mast.Identifier

	idx.Update("file:///typed-nil-expr.mut", &analyzer.Snapshot{
		Program: &mast.Program{
			Statements: []mast.Statement{
				&mast.ExpressionStatement{Expression: &mast.IfExpression{Condition: typedNilCondition}},
			},
			NodePositions: map[mast.Node]mast.Range{},
		},
	})
}

// WorkspaceSymbols is kept, unchanged. It is a genuinely global fuzzy query --
// the user is asking what exists anywhere, not what this file can see -- and
// scanning everything is the right answer to it.
func TestSymbolIndexWorkspaceSymbolsQueryAndLimit(t *testing.T) {
	idx := NewSymbolIndex()
	idx.Update("file:///defs-a.mut", analyzedSnapshot(t,
		"let alpha = 1;\n"+
			"let beta = 2;\n"+
			"struct Basket { id; }\n"))
	idx.Update("file:///defs-b.mut", analyzedSnapshot(t,
		"enum Better { One, Two }\n"+
			"let gamma = 3;\n"))

	all := idx.WorkspaceSymbols("", 100)
	if len(all) < 5 {
		t.Fatalf("workspace symbol count = %d, want at least 5", len(all))
	}

	filtered := idx.WorkspaceSymbols("be", 100)
	if len(filtered) != 2 {
		t.Fatalf("filtered symbol count = %d, want 2", len(filtered))
	}
	assertSymbolName(t, filtered, "beta")
	assertSymbolName(t, filtered, "Better")

	limited := idx.WorkspaceSymbols("", 2)
	if len(limited) != 2 {
		t.Fatalf("limited symbol count = %d, want 2", len(limited))
	}
}

func analyzedSnapshot(t *testing.T, src string) *analyzer.Snapshot {
	t.Helper()
	return analyzer.New().Analyze(src)
}

func assertSymbolName(t *testing.T, symbols []lsp.SymbolInformation, wantName string) {
	t.Helper()
	for _, symbol := range symbols {
		if symbol.Name == wantName {
			return
		}
	}
	t.Fatalf("symbol name %q not found", wantName)
}
