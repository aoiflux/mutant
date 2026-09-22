package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/cli"
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

// The loop the export left open: a store is written, and then read back through
// the same command that wrote it.
func TestGraphQueryReadsBackWhatGraphExportWrote(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "main.mut")
	if err := os.WriteFile(source,
		[]byte("let helper = fn(value) { return value; };\nhelper(1);\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "store")

	captureStdout(t, func() {
		if code := handleGraphCommand([]string{"mutant", "graph", "export", "--out", out, source}); code != 0 {
			t.Fatalf("export exit code %d, want 0", code)
		}
	})

	answered := captureStdout(t, func() {
		if code := handleGraphCommand([]string{
			"mutant", "graph", "query", "--store", out, "where", "helper",
		}); code != 0 {
			t.Fatalf("query exit code %d, want 0", code)
		}
	})
	assertContains(t, answered, "helper")
	assertContains(t, answered, "main.mut:1:5")
}

// A bad command line is exit 2 and a store that could not be answered about is
// exit 1. They are different failures and a script has to be able to tell them
// apart: the first means "you typed it wrong", the second means "that is not a
// graph store".
func TestGraphQuerySeparatesABadCommandLineFromAnUnreadableStore(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	stderr := captureStderr(t, func() {
		if code := handleGraphCommand([]string{"mutant", "graph", "query", "summary"}); code != 2 {
			t.Fatal("a query with no --store did not report a command-line error")
		}
	})
	if !strings.Contains(stderr, "--store is required") {
		t.Fatalf("the error does not say what is missing: %s", stderr)
	}

	stderr = captureStderr(t, func() {
		if code := handleGraphCommand([]string{
			"mutant", "graph", "query", "--store", root, "summary",
		}); code != 1 {
			t.Fatal("a directory that is not a store was not reported as a work failure")
		}
	})
	if !strings.Contains(stderr, "not a symbol graph") {
		t.Fatalf("the error does not say what is wrong with the directory: %s", stderr)
	}
}

// There is no query language, so a question that is not on the list has to be
// refused with the list rather than guessed at.
func TestAnUnknownQuestionIsRefusedWithTheOnesThatExist(t *testing.T) {
	stderr := captureStderr(t, func() {
		if code := handleGraphCommand([]string{
			"mutant", "graph", "query", "--store", t.TempDir(), "unused",
		}); code != 2 {
			t.Fatal("an unknown question was not a command-line error")
		}
	})
	assertContains(t, stderr, "not a question")
	for _, question := range cli.QueryQuestions() {
		assertContains(t, stderr, question.Name)
	}
}

// The help is built from the question list rather than written beside it, so a
// question cannot exist in one and not the other.
func TestGraphHelpListsEveryQuestionThatCanBeAsked(t *testing.T) {
	output := captureStdout(t, printGraphHelp)
	for _, question := range cli.QueryQuestions() {
		assertContains(t, output, question.Name)
	}
	assertContains(t, output, "mutant graph query --store")
}

// The help used to name an edge called CONTAINS. The export has never written
// one: the label is ENCLOSES, because "contains" is one of graphene's own
// built-in edge names and registering it would make one selector mean two
// things. A reader who took the help at its word and queried for CONTAINS would
// have got a parse error from a store that was perfectly fine.
func TestGraphHelpNamesTheEdgesTheExportActuallyWrites(t *testing.T) {
	output := captureStdout(t, printGraphHelp)
	for _, label := range []string{"DECLARES", "ENCLOSES", "REFERENCES", "IMPORTS", "USES_TYPE"} {
		assertContains(t, output, label)
	}
	if strings.Contains(output, "CONTAINS") {
		t.Fatal("the help names an edge called CONTAINS, which no store holds")
	}
}

// The help said "Two of the questions read every declaration record" above a
// list it generated from the same registry, and the list had one entry in it.
// Both halves come from the registry now, so the sentence cannot be wrong about
// the list printed under it -- and the test asserts the counting words are gone
// rather than that the count is right, because a count written in prose beside
// generated data is the defect, not the number it happened to hold.
func TestGraphHelpDoesNotCountTheScanningQuestionsInProse(t *testing.T) {
	output := captureStdout(t, printGraphHelp)

	for _, question := range cli.QueryQuestions() {
		if !question.Scans() {
			continue
		}
		assertContains(t, output, question.Cost)
	}

	for _, counted := range []string{
		"Two of the questions",
		"One of the questions",
		"Three of the questions",
	} {
		if strings.Contains(output, counted) {
			t.Fatalf("the help counts the scanning questions in prose (%q) instead of "+
				"printing the list", counted)
		}
	}
}

// `where` is an index lookup that reads every record when the name misses, and
// for a while it was filed under the cheaper of its two costs -- which is how
// the help came to promise a list of two and print a list of one.
func TestWhereIsDeclaredAsBothOfItsCosts(t *testing.T) {
	var where cli.QueryQuestion
	for _, question := range cli.QueryQuestions() {
		if question.Name == "where" {
			where = question
		}
	}
	if where.Name == "" {
		t.Fatal("there is no question called where")
	}
	if !where.Scans() {
		t.Fatal("`where` reads every declaration record on a miss and is not declared as doing so")
	}
	if !strings.Contains(where.Cost, "index") {
		t.Fatalf("`where` is an index lookup first and its cost does not say so: %q", where.Cost)
	}
}

// The store is read without being given a lock file it did not have, and the
// help has to say the narrower true thing rather than the wider false one.
func TestGraphHelpDoesNotClaimTheStoreIsUntouched(t *testing.T) {
	output := captureStdout(t, printGraphHelp)
	if strings.Contains(output, "nothing is written to it") {
		t.Fatal("the help claims nothing is written to the store; reading one that has no " +
			"graphene.lock would create it, which is why the read is lock-free instead")
	}
	assertContains(t, output, "graphene.lock")
}
