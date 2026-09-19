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

// `mutant lint` lints the files it was given as one program.
//
// A struct name, an enum name and a macro name all cross a module boundary
// written bare, and one file at a time cannot tell one of those from a typo --
// so it reported all three. The list of files the command already collects is
// the closure the editor builds by scanning a workspace root.
func TestHandleLintCommandSeesAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	writeInto(t, dir, "alpha.mut", "let twice = macro(x) {\n\tquote(unquote(x) + unquote(x));\n};\n"+
		"struct Point { x }\n"+
		"enum Colour { Red }\n")
	writeInto(t, dir, "main.mut", "import a \"alpha.mut\";\n"+
		"let p = Point{x: 1};\n"+
		"let c = Colour.Red;\n"+
		"let n = twice(21);\n"+
		"putln(p, c, n);\n")

	if code := handleLintCommand([]string{"mutant", "lint", "--strict", dir}); code != 0 {
		t.Fatalf("lint exit = %d on a program that compiles; every one of those "+
			"three names is declared in the file beside it", code)
	}
}

// And the other direction, in the same arrangement: a name nothing declares is
// still reported when the file is linted alongside its imports.
func TestHandleLintCommandStillReportsRealUndefinedNames(t *testing.T) {
	dir := t.TempDir()
	writeInto(t, dir, "alpha.mut", "struct Point { x }\n")
	writeInto(t, dir, "main.mut", "import a \"alpha.mut\";\nputln(notAThing);\n")

	if code := handleLintCommand([]string{"mutant", "lint", dir}); code != 1 {
		t.Fatalf("lint exit = %d, want 1 -- the rule must go quiet because an "+
			"import supplies the name, not because the file has an import", code)
	}
}

func writeInto(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
