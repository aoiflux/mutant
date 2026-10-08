package server

// M26-LSP-005: the background workspace scan re-indexed files the editor had
// open, under a different URI spelling.
//
// The scan asked the open-document store for pathToURI(path), which spells a
// Windows path as file:///C:/... . VS Code opens documents as file:///c%3A/...
// So on Windows the check missed every open document, and the scan then did
// two things: it added a second symbol-index entry for the same file, and it
// called sema.PutFile -- which is keyed by canonical path, not by URI -- with
// the copy from disk. The editor's unsaved declarations were replaced by what
// had been saved, and the importing file was told they did not exist.
//
// The rule the fix establishes: a URI string is the client's identity for a
// document and is kept exactly as the client sent it, because every response
// has to name it back. Any question about "is this the same file on disk" goes
// through canonicalPath. Mixing the two is what this row is.
//
// These tests need a path with a drive letter to have two spellings at all, so
// they skip where there is none rather than passing vacuously.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// vsCodeSpellingOf respells a canonical file URI the way VS Code sends one: a
// lower-case drive letter with a percent-encoded colon. Both spellings name the
// same file and the two strings are not equal, which is the whole problem.
func vsCodeSpellingOf(canonical string) (string, bool) {
	const prefix = "file:///"
	if !strings.HasPrefix(canonical, prefix) || len(canonical) < len(prefix)+2 {
		return "", false
	}
	if canonical[len(prefix)+1] != ':' {
		return "", false
	}
	drive := strings.ToLower(canonical[len(prefix) : len(prefix)+1])
	return prefix + drive + "%3A" + canonical[len(prefix)+2:], true
}

func TestTheScanLeavesAloneAFileTheEditorHasOpenUnderAnotherSpelling(t *testing.T) {
	root := writeModules(t, map[string]string{
		"lib.mut":  "let base = fn() { return 1; };\n",
		"main.mut": "import lib \"lib.mut\";\nlet a = lib.base();\n",
	})
	s := New(false)
	s.setRoots([]string{root})

	libPath := filepath.Join(root, "lib.mut")
	canonical := string(pathToURI(libPath))
	spelled, ok := vsCodeSpellingOf(canonical)
	if !ok {
		t.Skip("this host's paths carry no drive letter, so there is only one spelling")
	}
	vscode := lsp.DocumentUri(spelled)

	// The editor holds lib.mut with an unsaved edit: it declares a name the
	// copy on disk does not have. That is what makes a disk re-index visible
	// rather than merely redundant.
	open := "let base = fn() { return 1; };\nlet added = fn() { return 2; };\n"
	s.documents.Open(vscode, 1, open)
	s.evictScannedEntryFor(vscode)
	snapshot := s.analyzeDoc(vscode, open)
	s.setSnapshot(vscode, snapshot)
	s.safeSymbolUpdate(vscode, snapshot)
	s.safeSemaUpdate(vscode, snapshot)

	if indexed := s.indexFileFromDisk(libPath); indexed {
		t.Errorf("the scan indexed lib.mut from disk although the editor holds it open under %s; "+
			"an editor copy is authoritative", vscode)
	}

	for _, name := range []string{"base", "added"} {
		if got := len(s.symbols.WorkspaceSymbols(name, 100)); got != 1 {
			t.Errorf("%s is indexed %d times, want 1: the same file must not appear under two URIs", name, got)
		}
	}
}

func TestTheScanDoesNotReplaceAnOpenFilesFactsWithTheDiskCopys(t *testing.T) {
	root := t.TempDir()
	libDisk := "let base = fn() { return 1; };\n"
	libOpen := "let base = fn() { return 1; };\nlet added = fn() { return 2; };\n"
	mainSrc := "import lib \"lib.mut\";\nlet a = lib.added();\n"

	libPath := filepath.Join(root, "lib.mut")
	mainPath := filepath.Join(root, "main.mut")
	if err := os.WriteFile(libPath, []byte(libDisk), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainPath, []byte(mainSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	s := New(false)
	s.setRoots([]string{root})

	spelled, ok := vsCodeSpellingOf(string(pathToURI(libPath)))
	if !ok {
		t.Skip("this host's paths carry no drive letter, so there is only one spelling")
	}
	libURI := lsp.DocumentUri(spelled)
	mainURI := pathToURI(mainPath)

	s.documents.Open(libURI, 1, libOpen)
	s.evictScannedEntryFor(libURI)
	libSnapshot := s.analyzeDoc(libURI, libOpen)
	s.setSnapshot(libURI, libSnapshot)
	s.safeSymbolUpdate(libURI, libSnapshot)
	s.safeSemaUpdate(libURI, libSnapshot)

	s.documents.Open(mainURI, 1, mainSrc)
	s.evictScannedEntryFor(mainURI)

	diagnosticsForMain := func() int {
		snapshot := s.analyzeDoc(mainURI, mainSrc)
		s.setSnapshot(mainURI, snapshot)
		return len(snapshot.ModuleMemberDiagnostics())
	}

	before := diagnosticsForMain()
	if before != 0 {
		t.Fatalf("main.mut has %d module-member diagnostics before the scan, want 0: the editor's "+
			"lib.mut declares added, so lib.added resolves", before)
	}

	s.indexFileFromDisk(libPath)

	if after := diagnosticsForMain(); after != before {
		t.Errorf("main.mut went from %d to %d module-member diagnostics across a scan that changed "+
			"nothing about main.mut: the copy of lib.mut on disk replaced the open one", before, after)
	}
}

func TestTheScanStillIndexesAFileNoEditorHasOpen(t *testing.T) {
	// The false-refusal guard. The scan exists so that an import of an
	// unopened file resolves, and a check that skipped everything would pass
	// the two tests above and break the feature.
	root := writeModules(t, map[string]string{
		"lib.mut":  "let base = fn() { return 1; };\n",
		"main.mut": "import lib \"lib.mut\";\nlet a = lib.base();\n",
	})
	s := New(false)
	s.setRoots([]string{root})

	libPath := filepath.Join(root, "lib.mut")
	if indexed := s.indexFileFromDisk(libPath); !indexed {
		t.Fatal("the scan skipped lib.mut although no editor has it open")
	}
	if got := len(s.symbols.WorkspaceSymbols("base", 100)); got != 1 {
		t.Errorf("base is indexed %d times after a scan of an unopened file, want 1", got)
	}
}

func TestTheScanLeavesAloneAFileOpenUnderTheCanonicalSpelling(t *testing.T) {
	// The case that always worked, kept so that the fix cannot be read as
	// having moved the behaviour rather than widened it.
	root := writeModules(t, map[string]string{
		"lib.mut":  "let base = fn() { return 1; };\n",
		"main.mut": "import lib \"lib.mut\";\nlet a = lib.base();\n",
	})
	s := New(false)
	s.setRoots([]string{root})

	libPath := filepath.Join(root, "lib.mut")
	uri := pathToURI(libPath)
	open := "let base = fn() { return 1; };\nlet added = fn() { return 2; };\n"
	s.documents.Open(uri, 1, open)
	s.setSnapshot(uri, s.analyzeDoc(uri, open))

	if indexed := s.indexFileFromDisk(libPath); indexed {
		t.Error("the scan indexed lib.mut from disk although the editor holds it open under the " +
			"canonical spelling")
	}
}
