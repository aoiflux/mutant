package main

import (
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

func TestRunMutantSourceResults(t *testing.T) {
	// Boolean result.
	res, err := runMutantSource("1 + 1 == 2;")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b, ok := res.(*object.Boolean); !ok || !b.Value {
		t.Fatalf("expected Boolean(true), got %#v", res)
	}

	// Runtime error surfaces as a Go error.
	if _, err := runMutantSource("1 / 0;"); err == nil {
		t.Fatal("expected a runtime error for division by zero")
	}

	// Parse error surfaces as a Go error.
	if _, err := runMutantSource("let = ;"); err == nil {
		t.Fatal("expected a parse error")
	}

	// Non-boolean final value.
	res, err = runMutantSource("let x = 5;\nx;")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if i, ok := res.(*object.Integer); !ok || i.Value != 5 {
		t.Fatalf("expected Integer(5), got %#v", res)
	}
}

func TestRunTestFilePassFail(t *testing.T) {
	cases := []struct {
		name   string
		src    string
		wantOK bool
	}{
		{"true", "1 + 1 == 2;", true},
		{"false", "1 + 1 == 3;", false},
		{"runtime-error", "1 / 0;", false},
		{"non-bool", "let x = 5;\nx;", true},
		{"ends-in-let", "let x = 5;", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, reason := runTestFile(c.src)
			if ok != c.wantOK {
				t.Fatalf("runTestFile(%q) ok=%v (reason %q), want %v", c.src, ok, reason, c.wantOK)
			}
		})
	}
}

func TestHandleTestCommandExitCodes(t *testing.T) {
	dir := t.TempDir()
	mustWrite := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("pass_test.mut", "1 + 1 == 2;\n")
	mustWrite("helper.mut", "let a = 1;\n") // not a *_test.mut -> ignored

	if code := handleTestCommand([]string{"mutant", "test", dir}); code != 0 {
		t.Fatalf("all-passing test dir exit = %d, want 0", code)
	}

	mustWrite("fail_test.mut", "1 + 1 == 3;\n")
	if code := handleTestCommand([]string{"mutant", "test", dir}); code != 1 {
		t.Fatalf("dir with a failing test exit = %d, want 1", code)
	}
}

func TestCollectMutantTestFilesFiltersSuffix(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a_test.mut", "b_test.mut", "helper.mut", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("let a = 1;\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files, err := collectMutantTestFiles([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 *_test.mut files, got %d: %v", len(files), files)
	}
}
