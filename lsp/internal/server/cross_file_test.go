package server

import (
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// What crosses a file boundary, and what does not.
//
// These replace eight tests that asserted the opposite. Those opened two
// documents with no import between them -- `let shared = 1;` here, `shared;`
// there -- and required definition, references, prepare-rename and rename to
// connect them by spelling. The compiler does not: an import binds one
// namespace, and a name declared in another file is not in this file's scope
// because it happens to match.
//
// There are exactly two ways a use can name a declaration in another file, and
// both are covered here in both directions:
//
//   - a struct or enum name, written bare, because type names are program-global;
//   - a value, written `alias.name` through an import bound to its module.
//
// Every negative is paired with a positive at the same position, so that a
// refusal means the rule held rather than that the cursor landed on nothing.

const (
	typeLib   = "struct Point { x, y };\nlet helper = fn() { return 1; };\n"
	typeUser  = "import lib \"lib.mut\";\nlet p = Point{x: 1, y: 2};\n"
	onPointIn = 8 // `let p = Point{...}` -- Point begins at character 8.
)

func TestGoToDefinitionFollowsABareTypeIntoTheModuleThatDeclaresIt(t *testing.T) {
	root := writeModules(t, map[string]string{
		"lib.mut":  typeLib,
		"main.mut": typeUser,
	})
	s, uri := serverOver(t, root, "main.mut")

	result, err := s.definition(nil, &lsp.DefinitionParams{
		TextDocumentPositionParams: lsp.TextDocumentPositionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: uri},
			Position:     lsp.Position{Line: 1, Character: onPointIn},
		},
	})
	if err != nil {
		t.Fatalf("definition returned error: %v", err)
	}
	location, ok := result.(*lsp.Location)
	if !ok || location == nil {
		t.Fatalf("definition result type = %T, want *Location", result)
	}
	if want := pathToURI(root + "/lib.mut"); location.URI != want {
		t.Fatalf("definition URI = %q, want %q", location.URI, want)
	}
	// `struct Point` -- the name begins at character 7, and the range covers the
	// name alone rather than the declaration.
	if location.Range.Start.Line != 0 || location.Range.Start.Character != 7 {
		t.Fatalf("definition start = %+v, want line 0 char 7", location.Range.Start)
	}
}

// The bug the old index shipped: a jump into a file nothing imported. The same
// position with the import present proves the position is right.
func TestGoToDefinitionDoesNotFollowABareTypeIntoAnUnimportedModule(t *testing.T) {
	withoutImport := writeModules(t, map[string]string{
		"lib.mut":  typeLib,
		"main.mut": "let unrelated = 0;\nlet p = Point{x: 1, y: 2};\n",
	})
	s, uri := serverOver(t, withoutImport, "main.mut")
	result, err := s.definition(nil, &lsp.DefinitionParams{
		TextDocumentPositionParams: lsp.TextDocumentPositionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: uri},
			Position:     lsp.Position{Line: 1, Character: onPointIn},
		},
	})
	if err != nil {
		t.Fatalf("definition returned error: %v", err)
	}
	if location, jumped := result.(*lsp.Location); jumped && location != nil {
		t.Fatalf("jumped to %q, which main.mut never imports", location.URI)
	}

	withImport := writeModules(t, map[string]string{
		"lib.mut":  typeLib,
		"main.mut": typeUser,
	})
	s2, uri2 := serverOver(t, withImport, "main.mut")
	result2, err := s2.definition(nil, &lsp.DefinitionParams{
		TextDocumentPositionParams: lsp.TextDocumentPositionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: uri2},
			Position:     lsp.Position{Line: 1, Character: onPointIn},
		},
	})
	if err != nil {
		t.Fatalf("definition returned error: %v", err)
	}
	if _, jumped := result2.(*lsp.Location); !jumped {
		t.Fatal("the same position resolves nothing even with the import, so the " +
			"refusal above proves nothing")
	}
}

// A value is not a type. `helper` is declared in a module main.mut imports, and
// the compiler still calls it "undefined variable: helper" -- an import binds
// one namespace and nothing else comes with it.
func TestGoToDefinitionDoesNotFollowABareValueIntoAnImportedModule(t *testing.T) {
	root := writeModules(t, map[string]string{
		"lib.mut":  typeLib,
		"main.mut": "import lib \"lib.mut\";\nlet n = helper();\n",
	})
	s, uri := serverOver(t, root, "main.mut")

	result, err := s.definition(nil, &lsp.DefinitionParams{
		TextDocumentPositionParams: lsp.TextDocumentPositionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: uri},
			Position:     lsp.Position{Line: 1, Character: 9},
		},
	})
	if err != nil {
		t.Fatalf("definition returned error: %v", err)
	}
	if location, jumped := result.(*lsp.Location); jumped && location != nil {
		t.Fatalf("jumped to %q for a bare value; the compiler refuses to compile "+
			"that program", location.URI)
	}
}

// The uses of a module member are the ones written through a namespace bound to
// its module -- in every file that binds one, under whatever name that file
// chose.
func TestReferencesToAModuleMemberSpanTheFilesThatImportIt(t *testing.T) {
	root := writeModules(t, map[string]string{
		"lib.mut":   "let mean = fn(xs) { return 0; };\n",
		"main.mut":  "import stats \"lib.mut\";\nlet a = stats.mean([1]);\n",
		"other.mut": "import s2 \"lib.mut\";\nlet b = s2.mean([2]);\nlet c = s2.mean([3]);\n",
		"stray.mut": "let mean = 0;\nlet d = mean;\n",
	})
	s, uri := serverOver(t, root, "main.mut")

	result, err := s.references(nil, &lsp.ReferenceParams{
		TextDocumentPositionParams: lsp.TextDocumentPositionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: uri},
			// `let a = stats.mean(...)` -- mean begins at character 14.
			Position: lsp.Position{Line: 1, Character: 15},
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
	if got := byURI[pathToURI(root+"/main.mut")]; got != 1 {
		t.Fatalf("references in main.mut = %d, want 1: %+v", got, result)
	}
	if got := byURI[pathToURI(root+"/other.mut")]; got != 2 {
		t.Fatalf("references in other.mut = %d, want 2 (both written through the "+
			"alias s2): %+v", got, result)
	}
	if got := byURI[pathToURI(root+"/stray.mut")]; got != 0 {
		t.Fatalf("references in stray.mut = %d, want 0: it declares its own mean "+
			"and imports nothing", got)
	}
}

// Renaming a module member has to reach the declaration and every importer's
// call site, and has to leave the namespace in front of it alone.
func TestRenamingAModuleMemberEditsTheDeclarationAndEveryCallSite(t *testing.T) {
	root := writeModules(t, map[string]string{
		"lib.mut":   "let mean = fn(xs) { return 0; };\n",
		"main.mut":  "import stats \"lib.mut\";\nlet a = stats.mean([1]);\n",
		"other.mut": "import s2 \"lib.mut\";\nlet b = s2.mean([2]);\n",
	})
	s, uri := serverOver(t, root, "main.mut")

	edit, err := s.rename(nil, &lsp.RenameParams{
		TextDocumentPositionParams: lsp.TextDocumentPositionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: uri},
			Position:     lsp.Position{Line: 1, Character: 15},
		},
		NewName: "average",
	})
	if err != nil {
		t.Fatalf("rename returned error: %v", err)
	}
	if edit == nil || edit.Changes == nil {
		t.Fatal("rename produced no edits")
	}

	for _, rel := range []string{"/lib.mut", "/main.mut", "/other.mut"} {
		edits := edit.Changes[pathToURI(root+rel)]
		if len(edits) != 1 {
			t.Fatalf("%s got %d edits, want 1: %+v", rel, len(edits), edit.Changes)
		}
		if edits[0].NewText != "average" {
			t.Fatalf("%s edit text = %q, want average", rel, edits[0].NewText)
		}
		// Four characters wide: the member name, never the `stats.` in front.
		if span := edits[0].Range.End.Character - edits[0].Range.Start.Character; span != 4 {
			t.Fatalf("%s edit spans %d characters, want 4 (mean alone)", rel, span)
		}
	}
}

// A local binding has no meaning outside its file, so there is nothing for a
// workspace-wide rename to do and prepare-rename must not offer one. The
// snapshot's own rename still handles it; this is only about the cross-file
// path declining.
func TestPrepareRenameDeclinesANameWithNoCrossFileMeaning(t *testing.T) {
	root := writeModules(t, map[string]string{
		"lib.mut":  typeLib,
		"main.mut": "import lib \"lib.mut\";\nlet n = helper();\n",
	})
	s, uri := serverOver(t, root, "main.mut")

	snapshot, ok := s.snapshot(uri)
	if !ok {
		t.Fatal("no snapshot for the opened document")
	}
	onHelper := lsp.Position{Line: 1, Character: 9}
	if _, ok := s.workspaceDeclarationAt(snapshot, uri, onHelper); ok {
		t.Fatal("a bare value in another module was offered as a rename target; " +
			"renaming it here would not change the program the compiler sees")
	}
}

// The reverse direction for the type case: the declaring file's own view. Asking
// about `Point` where it is declared must find the importer's use, and must not
// find a same-named use in a file that never imports it.
func TestReferencesToATypeReachImportersAndNothingElse(t *testing.T) {
	root := writeModules(t, map[string]string{
		"lib.mut":   typeLib,
		"main.mut":  typeUser,
		"stray.mut": "let q = Point{x: 9, y: 9};\n",
	})
	s, uri := serverOver(t, root, "lib.mut")

	result, err := s.references(nil, &lsp.ReferenceParams{
		TextDocumentPositionParams: lsp.TextDocumentPositionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: uri},
			Position:     lsp.Position{Line: 0, Character: 8},
		},
		Context: lsp.ReferenceContext{IncludeDeclaration: false},
	})
	if err != nil {
		t.Fatalf("references returned error: %v", err)
	}

	sawImporter := false
	for _, location := range result {
		if location.URI == pathToURI(root+"/stray.mut") {
			t.Fatalf("a use in stray.mut was reported; it imports nothing: %+v", result)
		}
		if location.URI == pathToURI(root+"/main.mut") {
			sawImporter = true
		}
	}
	if !sawImporter {
		t.Fatalf("the use in main.mut was not reported, so the refusal above "+
			"proves nothing: %+v", result)
	}
}

// A local binding that shadows a top-level name of the same spelling.
//
// Without the top-level guard this position looks like a declaration the
// workspace knows: the name matches a top-level symbol, so the kind lookup
// succeeds -- but the location handed back is the LOCAL one. The editor would
// then offer a rename that rewrote the inner binding and every importer's use of
// the outer one, which are different declarations that happen to share a name.
func TestALocalBindingIsNotOfferedAsTheTopLevelOneItShadows(t *testing.T) {
	root := writeModules(t, map[string]string{
		"lib.mut": "struct Shape { n };\n",
		// main.mut declares Shape at its top level AND rebinds it inside a
		// function. Both halves matter: the top-level one is what makes the name
		// look like something the workspace knows, and the inner one is the
		// declaration the position below actually refers to.
		"main.mut": "import lib \"lib.mut\";\n" +
			"let Shape = 1;\n" +
			"let f = fn() {\n" +
			"\tlet Shape = 2;\n" +
			"\treturn Shape;\n" +
			"};\n",
	})
	s, uri := serverOver(t, root, "main.mut")
	snapshot, ok := s.snapshot(uri)
	if !ok {
		t.Fatal("no snapshot for the opened document")
	}

	// `	return Shape;` -- the use of the local binding.
	onLocalUse := lsp.Position{Line: 4, Character: 10}
	if declared, offered := s.workspaceDeclarationAt(snapshot, uri, onLocalUse); offered {
		t.Fatalf("a local binding was offered as the cross-file declaration %s in "+
			"%s; nothing outside this function can name it", declared.name, declared.module)
	}

	// The same file, the same spelling, at a position that really is a
	// cross-file reference: without this the refusal above could just as well
	// mean the position landed on nothing.
	sameName := writeModules(t, map[string]string{
		"lib.mut":  "struct Shape { n };\n",
		"main.mut": "import lib \"lib.mut\";\nlet s = Shape{n: 1};\n",
	})
	s2, uri2 := serverOver(t, sameName, "main.mut")
	snapshot2, _ := s2.snapshot(uri2)
	if _, offered := s2.workspaceDeclarationAt(snapshot2, uri2, lsp.Position{Line: 1, Character: 9}); !offered {
		t.Fatal("a genuine cross-file use of Shape was not offered either, so the " +
			"refusal above proves nothing")
	}
}
