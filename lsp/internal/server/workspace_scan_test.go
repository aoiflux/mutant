package server

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tliron/glsp"
	lsp "github.com/tliron/glsp/protocol_3_16"
)

func TestPathURIRoundTrip(t *testing.T) {
	var samples []string
	if runtime.GOOS == "windows" {
		samples = []string{`O:\project\mutant\x.mut`, `C:\Users\a b\file.mut`}
	} else {
		samples = []string{"/home/a/x.mut", "/tmp/a b/file.mut"}
	}
	for _, p := range samples {
		uri := pathToURI(p)
		back, ok := uriToPath(uri)
		if !ok {
			t.Fatalf("uriToPath(%q) failed for %q", uri, p)
		}
		if canonicalPath(back) != canonicalPath(p) {
			t.Fatalf("round trip mismatch: %q -> %q -> %q", p, uri, back)
		}
	}
}

func TestScanWorkspaceIndexesUnopenedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lib.mut"), []byte("let shared_helper = fn() { return 1; };\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A pruned directory whose contents must NOT be indexed.
	vendor := filepath.Join(dir, "node_modules")
	if err := os.MkdirAll(vendor, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendor, "ignored.mut"), []byte("let ignored_symbol = 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := New(false)
	s.roots = []string{dir}
	s.scanWorkspace()

	syms := s.symbols.WorkspaceSymbols("shared_helper", 10)
	if len(syms) == 0 {
		t.Fatal("expected the disk-scanned symbol to be indexed")
	}
	if got := s.symbols.WorkspaceSymbols("ignored_symbol", 10); len(got) != 0 {
		t.Fatalf("node_modules content must be pruned, found %d", len(got))
	}
}

func TestOpenEvictsStaleScannedEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mod.mut")
	if err := os.WriteFile(path, []byte("let only_def = 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := New(false)
	initializeServer(t, s)
	s.roots = []string{dir}
	s.scanWorkspace()

	// Open the same file under its canonical URI; there must be exactly one
	// definition afterward (no duplicate/ambiguous entry).
	uri := string(pathToURI(path))
	openMutantDoc(t, s, uri, "let only_def = 1;\nonly_def;\n")

	if _, ok := s.symbols.UniqueTopLevelDefinition("only_def", "file:///other.mut"); !ok {
		t.Fatal("expected a unique cross-file definition for only_def after open")
	}
}

func TestDidChangeWatchedFilesCreateAndDelete(t *testing.T) {
	dir := t.TempDir()
	s := New(false)
	s.roots = []string{dir}

	path := filepath.Join(dir, "watched.mut")
	if err := os.WriteFile(path, []byte("let watched_def = 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	uri := pathToURI(path)

	// Created -> indexed.
	if err := s.didChangeWatchedFiles(&glsp.Context{}, &lsp.DidChangeWatchedFilesParams{
		Changes: []lsp.FileEvent{{URI: uri, Type: lsp.FileChangeTypeCreated}},
	}); err != nil {
		t.Fatal(err)
	}
	if len(s.symbols.WorkspaceSymbols("watched_def", 10)) == 0 {
		t.Fatal("created file should be indexed")
	}

	// Deleted -> removed.
	if err := s.didChangeWatchedFiles(&glsp.Context{}, &lsp.DidChangeWatchedFilesParams{
		Changes: []lsp.FileEvent{{URI: uri, Type: lsp.FileChangeTypeDeleted}},
	}); err != nil {
		t.Fatal(err)
	}
	if len(s.symbols.WorkspaceSymbols("watched_def", 10)) != 0 {
		t.Fatal("deleted file should be removed from the index")
	}
}
