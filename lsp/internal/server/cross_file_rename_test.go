package server

// M26-LSP-003: a rename started on a module's declaration never edited the
// importers.
//
// rename consulted the workspace-wide locations only when the file-local
// result came back empty. With the cursor on the declaration it never is -- it
// holds the declaration itself -- so the one position a rename is most often
// started from, F2 on a definition, was the one position that reached no
// importer. references() for the same position merged them correctly, which is
// what says the two paths had drifted rather than that the data was missing.
//
// The existing cross-file rename test starts from the CALL SITE, where the
// local result is empty and the workspace path therefore gets its chance. That
// is why it passed throughout.
//
// Each test here asks references() the same question in the same run, so a
// failure shows both numbers and there is no doubt about whether the locations
// were findable.

import (
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// renameAndReferencesAt returns how many files a rename edited and how many
// locations references found, from one position.
func renameAndReferencesAt(t *testing.T, s *Server, uri lsp.DocumentUri, position lsp.Position) (*lsp.WorkspaceEdit, []lsp.Location) {
	t.Helper()
	refs, err := s.references(nil, &lsp.ReferenceParams{
		TextDocumentPositionParams: lsp.TextDocumentPositionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: uri},
			Position:     position,
		},
		Context: lsp.ReferenceContext{IncludeDeclaration: true},
	})
	if err != nil {
		t.Fatalf("references returned error: %v", err)
	}
	edit, err := s.rename(nil, &lsp.RenameParams{
		TextDocumentPositionParams: lsp.TextDocumentPositionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: uri},
			Position:     position,
		},
		NewName: "average",
	})
	if err != nil {
		t.Fatalf("rename returned error: %v", err)
	}
	return edit, refs
}

func TestRenamingFromTheDeclarationEditsEveryImporter(t *testing.T) {
	// other.mut imports under a different alias on purpose: the edit has to
	// cover the member name and never the alias in front of it, and a second
	// alias is what shows the member name is what was matched.
	root := writeModules(t, map[string]string{
		"lib.mut":   "let mean = fn(xs) { return 0; };\n",
		"main.mut":  "import stats \"lib.mut\";\nlet a = stats.mean([1]);\n",
		"other.mut": "import s2 \"lib.mut\";\nlet b = s2.mean([2]);\n",
		// stray.mut declares its own mean and imports nothing, so it must not
		// be touched: this is the false-positive guard.
		"stray.mut": "let mean = fn(xs) { return 1; };\nlet c = mean([3]);\n",
	})
	s, uri := serverOver(t, root, "lib.mut")

	// `let mean = ...` -- the name begins at character 4.
	edit, refs := renameAndReferencesAt(t, s, uri, lsp.Position{Line: 0, Character: 4})
	if edit == nil || edit.Changes == nil {
		t.Fatalf("rename from the declaration produced no edits at all, while references found %d locations", len(refs))
	}

	for _, rel := range []string{"/lib.mut", "/main.mut", "/other.mut"} {
		edits := edit.Changes[pathToURI(root+rel)]
		if len(edits) != 1 {
			t.Errorf("%s got %d edits, want 1 -- references found %d locations from the same position, "+
				"so the locations were there to be used", rel, len(edits), len(refs))
			continue
		}
		if edits[0].NewText != "average" {
			t.Errorf("%s edit text = %q, want average", rel, edits[0].NewText)
		}
		// Four characters wide: the member name, never the alias in front.
		if span := edits[0].Range.End.Character - edits[0].Range.Start.Character; span != 4 {
			t.Errorf("%s edit spans %d characters, want 4 (mean alone)", rel, span)
		}
	}

	if edits := edit.Changes[pathToURI(root+"/stray.mut")]; len(edits) != 0 {
		t.Errorf("stray.mut got %d edits, want 0: it declares its own mean and imports nothing", len(edits))
	}
}

func TestRenamingFromACallSiteStillEditsEveryImporter(t *testing.T) {
	// The position the old path did handle. It is kept because the fix moved
	// the merge, and a merge that only works from the declaration would be the
	// same defect pointing the other way.
	root := writeModules(t, map[string]string{
		"lib.mut":   "let mean = fn(xs) { return 0; };\n",
		"main.mut":  "import stats \"lib.mut\";\nlet a = stats.mean([1]);\n",
		"other.mut": "import s2 \"lib.mut\";\nlet b = s2.mean([2]);\n",
	})
	s, uri := serverOver(t, root, "main.mut")

	edit, refs := renameAndReferencesAt(t, s, uri, lsp.Position{Line: 1, Character: 15})
	if edit == nil || edit.Changes == nil {
		t.Fatalf("rename from the call site produced no edits, while references found %d locations", len(refs))
	}
	for _, rel := range []string{"/lib.mut", "/main.mut", "/other.mut"} {
		if edits := edit.Changes[pathToURI(root+rel)]; len(edits) != 1 {
			t.Errorf("%s got %d edits, want 1", rel, len(edits))
		}
	}
}

func TestRenameEditsNoSpanTwice(t *testing.T) {
	// The fix appends the workspace locations to the local ones, and the
	// declaration is in both sets. Without the dedupe that follows, the
	// declaring file would receive the same edit twice -- two edits over one
	// span, which an LSP client is entitled to refuse or to apply twice.
	root := writeModules(t, map[string]string{
		"lib.mut":  "let mean = fn(xs) { return 0; };\n",
		"main.mut": "import stats \"lib.mut\";\nlet a = stats.mean([1]);\n",
	})
	s, uri := serverOver(t, root, "lib.mut")

	edit, _ := renameAndReferencesAt(t, s, uri, lsp.Position{Line: 0, Character: 4})
	if edit == nil || edit.Changes == nil {
		t.Fatal("rename produced no edits")
	}
	for docURI, edits := range edit.Changes {
		seen := map[lsp.Range]int{}
		for _, e := range edits {
			seen[e.Range]++
		}
		for rng, n := range seen {
			if n > 1 {
				t.Errorf("%s has %d edits over the same span %+v; an edit list must not overlap itself",
					docURI, n, rng)
			}
		}
	}
}

func TestReferencesAndRenameAgreeOnWhatTheyFound(t *testing.T) {
	// The property the fix really establishes: the two answer the same
	// question. They are not required to produce the same shape, but every
	// file references names must be a file rename edits, from any position
	// that can be renamed at all.
	root := writeModules(t, map[string]string{
		"lib.mut":   "let mean = fn(xs) { return 0; };\n",
		"main.mut":  "import stats \"lib.mut\";\nlet a = stats.mean([1]);\n",
		"other.mut": "import s2 \"lib.mut\";\nlet b = s2.mean([2]);\n",
	})

	for _, tt := range []struct {
		name     string
		open     string
		position lsp.Position
	}{
		{"from the declaration", "lib.mut", lsp.Position{Line: 0, Character: 4}},
		{"from an importer's call site", "main.mut", lsp.Position{Line: 1, Character: 15}},
		{"from the other importer's call site", "other.mut", lsp.Position{Line: 1, Character: 12}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, uri := serverOver(t, root, tt.open)
			edit, refs := renameAndReferencesAt(t, s, uri, tt.position)
			if len(refs) == 0 {
				t.Skip("references found nothing from this position, so there is nothing to compare")
			}
			if edit == nil || edit.Changes == nil {
				t.Fatalf("references found %d locations and rename produced no edits", len(refs))
			}
			for _, ref := range refs {
				if len(edit.Changes[ref.URI]) == 0 {
					t.Errorf("references names %s and rename edits nothing in it", ref.URI)
				}
			}
		})
	}
}
