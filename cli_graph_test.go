package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `graph` has to be a command everywhere the CLI decides what a word is.
//
// There are three such places and they are not one function: the handler table,
// isBuiltinCommand, and shouldAttemptEmbeddedRun. The last is the one that bites
// -- a released binary carries its program inside itself, and an argument it
// does not recognise as a command means "run the payload". A `graph` that were
// missing from that list would work perfectly during development and silently
// run the embedded program in a release build.
func TestGraphIsACommandEverywhereTheCLIDecidesWhatAWordIs(t *testing.T) {
	if _, registered := commandHandlers[GRAPHCMD]; !registered {
		t.Fatal("graph is not in the command table")
	}
	if !isBuiltinCommand(GRAPHCMD) {
		t.Fatal("isBuiltinCommand does not know graph, so `mutant graph ...` " +
			"would be treated as a file to run")
	}
	if shouldAttemptEmbeddedRun([]string{"mutant", GRAPHCMD, "export"}) {
		t.Fatal("a standalone binary would run its embedded payload instead of " +
			"exporting a graph")
	}
}

func TestGraphWithoutASubcommandExplainsItself(t *testing.T) {
	output := captureStdout(t, func() {
		if code := handleGraphCommand([]string{"mutant", "graph"}); code != 2 {
			t.Fatalf("exit code %d, want 2 for a usage error", code)
		}
	})
	assertContains(t, output, "mutant graph export")
	assertContains(t, output, "--out")
}

func TestGraphHelpIsReachableThroughTheHelpCommand(t *testing.T) {
	output := captureStdout(t, func() { printHelpTopic([]string{GRAPHCMD}) })
	assertContains(t, output, "symbol graph")
	assertContains(t, output, "REFERENCES")
}

func TestGeneralHelpListsGraph(t *testing.T) {
	output := captureStdout(t, printGeneralHelp)
	assertContains(t, output, "mutant graph export")
}

// --out has no default. A graph store is a directory of files, and guessing
// where to put one is how a tool ends up writing into a repository.
func TestGraphExportRequiresAnOutputDirectory(t *testing.T) {
	source := filepath.Join(t.TempDir(), "main.mut")
	if err := os.WriteFile(source, []byte("let x = 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	stderr := captureStderr(t, func() {
		code := handleGraphCommand([]string{"mutant", "graph", "export", source})
		if code != 2 {
			t.Fatalf("exit code %d, want 2", code)
		}
	})
	if !strings.Contains(stderr, "--out is required") {
		t.Fatalf("the error does not say what is missing: %s", stderr)
	}
}

func TestGraphExportWritesAStoreAndSaysWhatItWrote(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "main.mut")
	if err := os.WriteFile(source,
		[]byte("let helper = fn() { return 1; };\nhelper();\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "store")

	output := captureStdout(t, func() {
		code := handleGraphCommand([]string{"mutant", "graph", "export", "--out", out, source})
		if code != 0 {
			t.Fatalf("exit code %d, want 0", code)
		}
	})

	assertContains(t, output, "1 modules")
	assertContains(t, output, "nodes")
	if entries, err := os.ReadDir(out); err != nil || len(entries) == 0 {
		t.Fatalf("nothing was written to %s: %v", out, err)
	}
}
