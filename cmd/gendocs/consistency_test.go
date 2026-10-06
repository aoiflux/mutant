package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/builtin"
)

// These are the checks on the checks.
//
// `gendocs -check` passed a tree it should have failed, so "the check runs" is
// not the same claim as "the check works", and the difference cost a broken
// HEAD twice on 2026-10-06. Each check here is pointed at a small tree that is
// wrong on purpose and has to say so, at the line a reader would look at.
//
// The trees are built under t.TempDir(), not in testdata, because the link
// check walks every Markdown file under the root it is given: a fixture with a
// deliberately dead link, committed inside the repository, would be found by
// the real run and reported as a real defect.

// The trees are built by writeTree, in limits_test.go, which already does
// exactly this for the limits scanner.

// proseTree holds every document checkProseCounts reads, each with a sentence
// that is right, so that a test can make exactly one of them wrong and the
// problems it gets back are the ones it asked for.
func proseTree(t *testing.T, override map[string]string) string {
	t.Helper()
	correct := fmt.Sprintf("The standard library is %d builtins across %d categories.\n",
		len(builtin.Builtins), len(categorySections))
	files := make(map[string]string, len(proseCountPaths)+1)
	for _, path := range proseCountPaths {
		files[path] = correct
	}
	for path, body := range override {
		if body == "" {
			delete(files, path)
			continue
		}
		files[path] = body
	}
	return writeTree(t, files)
}

// onlyProblem returns the single problem a check found, failing when it found
// any other number. A check that reports two things where one is wrong is as
// much use as one that reports nothing.
func onlyProblem(t *testing.T, check docCheck) docProblem {
	t.Helper()
	if len(check.problems) != 1 {
		t.Fatalf("%s: reported %d problems, want 1:\n%s",
			check.what, len(check.problems), strings.Join(problemLines(check), "\n"))
	}
	return check.problems[0]
}

func problemLines(check docCheck) []string {
	lines := make([]string, 0, len(check.problems))
	for _, problem := range check.problems {
		lines = append(lines, "  "+problem.String())
	}
	return lines
}

func TestAStaleProseCountIsReportedAtItsLine(t *testing.T) {
	root := proseTree(t, map[string]string{
		"docs/COOKBOOK.md": "# Cookbook\n\nThe standard library is 693 builtins.\n",
	})
	check, err := checkProseCounts(root)
	if err != nil {
		t.Fatalf("checking prose counts: %v", err)
	}

	problem := onlyProblem(t, check)
	if problem.path != "docs/COOKBOOK.md" || problem.line != 3 {
		t.Errorf("reported %s:%d, want docs/COOKBOOK.md:3", problem.path, problem.line)
	}
	if !strings.Contains(problem.text, "says 693 builtins") {
		t.Errorf("the problem does not say what the document claims: %s", problem.text)
	}
	if !strings.Contains(problem.text, fmt.Sprintf("the tree has %d", len(builtin.Builtins))) {
		t.Errorf("the problem does not say what the registry holds: %s", problem.text)
	}
}

// A count split over a line break is the shape that made this check search the
// flattened document, and it is the one a hard-wrapped document produces.
func TestAProseCountIsFoundAcrossALineBreak(t *testing.T) {
	root := proseTree(t, map[string]string{
		"docs/COMPARISON.md": "# Comparison\n\nA toolchain for forensic work. 459\nbuiltins across 34 categories.\n",
	})
	check, err := checkProseCounts(root)
	if err != nil {
		t.Fatalf("checking prose counts: %v", err)
	}
	if len(check.problems) != 2 {
		t.Fatalf("reported %d problems, want 2 (the builtin count and the category count):\n%s",
			len(check.problems), strings.Join(problemLines(check), "\n"))
	}
	if check.problems[0].line != 3 {
		t.Errorf("the builtin count was reported at line %d, want 3: %s",
			check.problems[0].line, check.problems[0].text)
	}
}

func TestADocumentListedButMissingIsReported(t *testing.T) {
	root := proseTree(t, map[string]string{"docs/EXECUTION_MODES.md": ""})
	check, err := checkProseCounts(root)
	if err != nil {
		t.Fatalf("checking prose counts: %v", err)
	}

	problem := onlyProblem(t, check)
	if problem.path != "docs/EXECUTION_MODES.md" || !strings.Contains(problem.text, "not in the tree") {
		t.Errorf("want docs/EXECUTION_MODES.md reported as absent, got %s", problem)
	}
}

// A check that has stopped matching anything passes every document ever
// written, and says so in the same words it uses for a tree that is right.
// That is the failure this whole file is about, so it gets its own test.
func TestACheckThatMatchesNothingDoesNotPass(t *testing.T) {
	root := proseTree(t, map[string]string{})
	for _, path := range proseCountPaths {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(path)),
			[]byte("# Nothing numerical here.\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	check, err := checkProseCounts(root)
	if err != nil {
		t.Fatalf("checking prose counts: %v", err)
	}
	if len(check.problems) != 0 {
		t.Fatalf("a tree with no claims in it reported problems:\n%s",
			strings.Join(problemLines(check), "\n"))
	}
	if check.shortfall() == "" {
		t.Fatalf("examined %d claims and still called it a pass", check.examined)
	}
	if !strings.Contains(check.shortfall(), "the scanner is broken") {
		t.Errorf("the shortfall does not say what is wrong: %s", check.shortfall())
	}
}

func TestAStaleExampleCountIsReported(t *testing.T) {
	root := writeTree(t, map[string]string{
		"examples/one.mut":   "putf(\"{}\", 1);\n",
		"examples/two.mut":   "putf(\"{}\", 2);\n",
		"docs/COOKBOOK.md":   "# Cookbook\n\nThere are 97 runnable programs here.\n",
		"docs/EXAMPLES.txt":  "not markdown, and not counted\n",
		"examples/notes.txt": "not a program\n",
	})
	check, err := checkProseExampleCounts(root)
	if err != nil {
		t.Fatalf("checking example counts: %v", err)
	}

	problem := onlyProblem(t, check)
	if !strings.Contains(problem.text, "says 97 runnable programs") ||
		!strings.Contains(problem.text, "the tree has 2") {
		t.Errorf("want 97 against the two .mut programs, got %s", problem)
	}
}

func TestAStaleCategoryIndexRowIsReportedWithItsDeadAnchor(t *testing.T) {
	section := categorySections[0]
	root := writeTree(t, map[string]string{
		"docs/MUTANT_LANGUAGE_REFERENCE.md": fmt.Sprintf(
			"# Reference\n\n| Category | Builtins | What |\n| --- | --- | --- |\n"+
				"| [%s](CAPABILITY_REFERENCE.md#not-an-anchor) | 0 | %s |\n",
			section.heading, section.blurb),
	})
	check, err := checkCategoryIndex(root)
	if err != nil {
		t.Fatalf("checking the category index: %v", err)
	}
	if check.examined != 1 {
		t.Fatalf("examined %d rows, want the 1 written", check.examined)
	}

	// The row is wrong twice -- the count and the anchor -- and every other
	// category has no row at all, which is the third thing this check is for.
	wantProblems := 2 + len(categorySections) - 1
	if len(check.problems) != wantProblems {
		t.Fatalf("reported %d problems, want %d:\n%s", len(check.problems), wantProblems,
			strings.Join(problemLines(check), "\n"))
	}
	joined := strings.Join(problemLines(check), "\n")
	for _, want := range []string{
		fmt.Sprintf("says %s holds 0 builtins", section.heading),
		"links to #not-an-anchor",
		"the link is dead",
		"has no row for",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("no problem mentions %q:\n%s", want, joined)
		}
	}
	for _, problem := range check.problems[:2] {
		if problem.line != 5 {
			t.Errorf("the row's problem was reported at line %d, want 5: %s", problem.line, problem.text)
		}
	}
}

func TestADeadLinkAndADeadAnchorAreBothReported(t *testing.T) {
	root := writeTree(t, map[string]string{
		"docs/a.md": "# A\n\n" +
			"[gone](missing.md) and [nowhere](b.md#no-such-heading) and [here](b.md#real-heading).\n" +
			"[away](https://example.invalid/missing.md) is not ours to check.\n" +
			"```\n[fenced](missing.md)\n```\n",
		"docs/b.md": "# B\n\n## Real heading\n\nText.\n",
	})
	check, err := checkDocumentLinks(root)
	if err != nil {
		t.Fatalf("checking document links: %v", err)
	}
	if len(check.problems) != 2 {
		t.Fatalf("reported %d problems, want 2:\n%s", len(check.problems),
			strings.Join(problemLines(check), "\n"))
	}
	joined := strings.Join(problemLines(check), "\n")
	if !strings.Contains(joined, "link to missing.md, which does not exist") {
		t.Errorf("the missing file was not reported:\n%s", joined)
	}
	if !strings.Contains(joined, "no heading with anchor #no-such-heading") {
		t.Errorf("the dead anchor was not reported:\n%s", joined)
	}
	for _, problem := range check.problems {
		if problem.path != "docs/a.md" || problem.line != 3 {
			t.Errorf("reported %s:%d, want docs/a.md:3", problem.path, problem.line)
		}
	}
}

// The repository is the tree these checks exist for, so the last word is that
// they all pass on it. It is also what `gendocs -check` runs, which is what
// scripts/release_gate.{ps1,sh} runs.
func TestTheRepositoryIsConsistent(t *testing.T) {
	checks, err := checkDocumentConsistency(repoRoot)
	if err != nil {
		t.Fatalf("checking documentation consistency: %v", err)
	}
	if len(checks) == 0 {
		t.Fatal("checkDocumentConsistency ran nothing")
	}
	for _, check := range checks {
		if shortfall := check.shortfall(); shortfall != "" {
			t.Errorf("%s", shortfall)
		}
		for _, problem := range check.problems {
			t.Errorf("%s", problem)
		}
	}
}
