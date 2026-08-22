package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tliron/glsp"
	lsp "github.com/tliron/glsp/protocol_3_16"
)

func TestCodeLensReferenceCounts(t *testing.T) {
	s := New(false)
	initializeServer(t, s)
	uri := "file:///lens.mut"
	openMutantDoc(t, s, uri, "let helper = fn() { return 1; };\nhelper();\nhelper();\n")

	lenses, err := s.codeLens(&glsp.Context{}, &lsp.CodeLensParams{
		TextDocument: lsp.TextDocumentIdentifier{URI: uri},
	})
	if err != nil {
		t.Fatalf("codeLens error: %v", err)
	}
	if len(lenses) == 0 {
		t.Fatal("expected at least one code lens")
	}

	var helperLens *lsp.CodeLens
	for i := range lenses {
		if lenses[i].Command != nil && strings.Contains(lenses[i].Command.Title, "2 references") {
			helperLens = &lenses[i]
		}
	}
	if helperLens == nil {
		titles := make([]string, 0, len(lenses))
		for _, l := range lenses {
			if l.Command != nil {
				titles = append(titles, l.Command.Title)
			}
		}
		t.Fatalf("expected a '2 references' lens for helper, got titles %v", titles)
	}
	if helperLens.Command.Command != "mutant.showReferences" {
		t.Fatalf("lens command = %q, want mutant.showReferences", helperLens.Command.Command)
	}
	if len(helperLens.Command.Arguments) != 3 {
		t.Fatalf("expected 3 command arguments (uri, position, locations), got %d", len(helperLens.Command.Arguments))
	}
}

func TestCodeLensSingularReference(t *testing.T) {
	s := New(false)
	initializeServer(t, s)
	uri := "file:///lens2.mut"
	openMutantDoc(t, s, uri, "let once = 1;\nonce;\n")

	lenses, _ := s.codeLens(&glsp.Context{}, &lsp.CodeLensParams{
		TextDocument: lsp.TextDocumentIdentifier{URI: uri},
	})
	found := false
	for _, l := range lenses {
		if l.Command != nil && l.Command.Title == "1 reference" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected singular '1 reference' (no trailing s) for a single usage")
	}
}

func TestDocumentLinksResolveExistingFileOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data.bin"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	docPath := filepath.Join(dir, "prog.mut")
	src := "let a = fs_read(\"data.bin\");\nlet b = fs_read(\"missing.bin\");\n"
	if err := os.WriteFile(docPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	s := New(false)
	initializeServer(t, s)
	uri := string(pathToURI(docPath))
	openMutantDoc(t, s, uri, src)

	links, err := s.documentLinks(&glsp.Context{}, &lsp.DocumentLinkParams{
		TextDocument: lsp.TextDocumentIdentifier{URI: lsp.DocumentUri(uri)},
	})
	if err != nil {
		t.Fatalf("documentLinks error: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("expected exactly 1 link (only data.bin exists), got %d", len(links))
	}
	if links[0].Target == nil {
		t.Fatal("link target is nil")
	}
	if !strings.Contains(string(*links[0].Target), "data.bin") {
		t.Fatalf("link target = %q, want it to reference data.bin", *links[0].Target)
	}
}
