package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
