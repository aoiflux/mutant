package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/policy/limitscan"
)

// limitsPath is the checked-in reference, relative to this package.
const limitsPath = "../../" + defaultLimitsPath

// TestLimitsReferenceIsUpToDate is the drift gate for the limits reference: a
// limit added, renamed, re-valued or re-explained without regenerating fails
// here rather than leaving the document quietly wrong.
func TestLimitsReferenceIsUpToDate(t *testing.T) {
	want, err := renderLimitsReference("../..")
	if err != nil {
		t.Fatalf("renderLimitsReference: %v", err)
	}
	got, err := os.ReadFile(filepath.FromSlash(limitsPath))
	if err != nil {
		t.Fatalf("reading %s: %v", limitsPath, err)
	}
	if normalizeNewlines(string(got)) != normalizeNewlines(want) {
		t.Fatalf("%s is out of date; run `go run ./cmd/gendocs`", defaultLimitsPath)
	}
}

// TestLimitsReferenceIsHostIndependent pins the two properties that keep the
// document the same on every machine: no absolute path from the host that
// rendered it, and no line numbers that move whenever unrelated code does.
func TestLimitsReferenceIsHostIndependent(t *testing.T) {
	doc, err := renderLimitsReference("../..")
	if err != nil {
		t.Fatalf("renderLimitsReference: %v", err)
	}
	abs, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{abs, filepath.ToSlash(abs)} {
		if strings.Contains(doc, leak) {
			t.Errorf("the limits reference contains the host path %q", leak)
		}
	}
	for _, line := range strings.Split(doc, "\n") {
		if strings.Contains(line, ".go:") {
			t.Errorf("the limits reference cites a line number: %s", line)
		}
	}
}

// writeTree writes a throwaway source tree for the reference to scan.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, src := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const (
	shippedMain = "package main\n\nimport \"mutant/a\"\n\nfunc main() { a.F() }\n"
	linkedLimit = "package a\n\n// maxThings bounds things.\n//\n//mutant:limit count\nconst maxThings = 500\n\nfunc F() int { return maxThings }\n"
)

// TestTheLimitsReferenceCountsWhatIsNotNamed is M26-LIM-003's regression test.
// The reference said, whatever the scan found, that every limit was a named
// constant and that "this is the list of them", while the budget held 174
// limits that were not. It now says how many the guard finds unnamed, and only
// when that is none does it say so.
func TestTheLimitsReferenceCountsWhatIsNotNamed(t *testing.T) {
	unnamed := writeTree(t, map[string]string{
		"main.go": shippedMain,
		"a/a.go":  linkedLimit + "\nconst maxUnnamed = 900\n\nconst maxAlsoUnnamed = 901\n",
	})
	doc, err := renderLimitsReference(unnamed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(doc, "The guard finds 2 limits that are not named yet; `policy/limit_budget.go` lists each one.") {
		t.Errorf("a tree with two unnamed limits should say so:\n%s", doc)
	}

	named := writeTree(t, map[string]string{"main.go": shippedMain, "a/a.go": linkedLimit})
	doc, err = renderLimitsReference(named)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(doc, "1 limit in 1 package bound a run. The guard finds no limit that is not named.") {
		t.Errorf("a tree with every limit named should say so:\n%s", doc)
	}
}

// TestTheReferenceSetsTheToolsApart pins the other half of M26-LIM-003: the
// reference listed a test helper's settle timeout and the guard's own message
// width as if they bounded a run. A package no shipped program is built from
// is listed after the rest, under its own heading.
func TestTheReferenceSetsTheToolsApart(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.go": shippedMain,
		"a/a.go":  linkedLimit,
		"b/b.go":  "package b\n\n// maxTool bounds a tool.\n//\n//mutant:limit count\nconst maxTool = 7\n",
	})
	doc, err := renderLimitsReference(root)
	if err != nil {
		t.Fatal(err)
	}
	run := strings.Index(doc, "\n## `a`\n")
	tools := strings.Index(doc, "\n## The tools around Mutant\n")
	tool := strings.Index(doc, "\n### `b`\n")
	if run < 0 || tools < 0 || tool < 0 || !(run < tools && tools < tool) {
		t.Errorf("the linked package should come first and the other under the tools heading:\n%s", doc)
	}
	if !strings.Contains(doc, "1 limit in 1 package bound a run. 1 limit in 1 package bound the tools around it.") {
		t.Errorf("the counts should keep the two apart:\n%s", doc)
	}
}

// TestEveryProgramIsShippedOrATool makes a new program choose a side: until it
// is in shippedPrograms or toolPrograms the reference cannot say whether its
// limits bound a run, and it refuses to render.
func TestEveryProgramIsShippedOrATool(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.go":         shippedMain,
		"a/a.go":          linkedLimit,
		"cmd/new/main.go": "package main\n\nfunc main() {}\n",
	})
	if _, err := renderLimitsReference(root); err == nil || !strings.Contains(err.Error(), "cmd/new") {
		t.Errorf("a program on neither list should stop the render and be named, got %v", err)
	}

	// The real tree: every program in it is on one list, and every name on
	// the lists is a program.
	if _, err := renderLimitsReference("../.."); err != nil {
		t.Fatal(err)
	}
	result, err := limitscan.Scan("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, program := range append(append([]string{}, shippedPrograms...), toolPrograms...) {
		if !result.Mains[program] {
			t.Errorf("%s is listed as a program in cmd/gendocs/limits.go, and the scan found no program there", program)
		}
	}
}
