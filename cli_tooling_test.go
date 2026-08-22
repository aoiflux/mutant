package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHandleFmtCommandInPlaceAndIdempotent(t *testing.T) {
	path := writeTemp(t, "messy.mut", "let   x=1\n")

	if code := handleFmtCommand([]string{"mutant", "fmt", path}); code != 0 {
		t.Fatalf("fmt exit = %d, want 0", code)
	}
	out, _ := os.ReadFile(path)
	if string(out) != "let x = 1;\n" {
		t.Fatalf("formatted file = %q, want %q", string(out), "let x = 1;\n")
	}
	// Idempotent: --check now passes.
	if code := handleFmtCommand([]string{"mutant", "fmt", "--check", path}); code != 0 {
		t.Fatalf("fmt --check on formatted file exit = %d, want 0", code)
	}
}

func TestHandleFmtCommandCheckFailsOnUnformatted(t *testing.T) {
	path := writeTemp(t, "messy.mut", "let   x=1\n")
	if code := handleFmtCommand([]string{"mutant", "fmt", "--check", path}); code != 1 {
		t.Fatalf("fmt --check on messy file exit = %d, want 1", code)
	}
	// --check must not modify the file.
	out, _ := os.ReadFile(path)
	if string(out) != "let   x=1\n" {
		t.Fatalf("--check modified the file: %q", string(out))
	}
}

func TestHandleFmtCommandNoPaths(t *testing.T) {
	if code := handleFmtCommand([]string{"mutant", "fmt"}); code != 2 {
		t.Fatalf("fmt with no paths exit = %d, want 2", code)
	}
}

func TestHandleLintCommandExitCodes(t *testing.T) {
	bad := writeTemp(t, "bad.mut", "let a = 1;\nputln(undefined_thing);\n")
	if code := handleLintCommand([]string{"mutant", "lint", bad}); code != 1 {
		t.Fatalf("lint with an error exit = %d, want 1", code)
	}

	clean := writeTemp(t, "clean.mut", "let a = 1;\nputln(a);\n")
	if code := handleLintCommand([]string{"mutant", "lint", clean}); code != 0 {
		t.Fatalf("lint on clean file exit = %d, want 0", code)
	}

	// A warning-only file passes by default but fails under --strict.
	warn := writeTemp(t, "warn.mut", "let unused_thing = 1;\nputln(1);\n")
	if code := handleLintCommand([]string{"mutant", "lint", warn}); code != 0 {
		t.Fatalf("lint (default) on warning-only file exit = %d, want 0", code)
	}
	if code := handleLintCommand([]string{"mutant", "lint", "--strict", warn}); code != 1 {
		t.Fatalf("lint --strict on warning-only file exit = %d, want 1", code)
	}
}

func TestCollectMutantSourceFilesWalksDirs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.mut"), []byte("let a = 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "node_modules")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "skip.mut"), []byte("let b = 2;\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := collectMutantSourceFiles([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file (node_modules pruned), got %d: %v", len(files), files)
	}
}
