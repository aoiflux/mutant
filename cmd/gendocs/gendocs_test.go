package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/builtin"
)

// referencePath is the checked-in document, relative to this package.
const referencePath = "../../" + defaultOutputPath

// TestCapabilityReferenceIsUpToDate is the drift gate. The reference claims to
// be generated from builtin/metadata.go; this makes that claim enforceable, so
// adding or changing a builtin without regenerating fails the build rather than
// leaving the catalog quietly wrong.
func TestCapabilityReferenceIsUpToDate(t *testing.T) {
	want, err := renderDocument()
	if err != nil {
		t.Fatalf("renderDocument: %v", err)
	}

	got, err := os.ReadFile(filepath.FromSlash(referencePath))
	if err != nil {
		t.Fatalf("reading %s: %v", referencePath, err)
	}

	// The working tree may be checked out with CRLF endings, which says nothing
	// about whether the content drifted.
	if normalizeNewlines(string(got)) != normalizeNewlines(want) {
		t.Fatalf("%s is out of date; run `go run ./cmd/gendocs`", defaultOutputPath)
	}
}

// TestEveryCategoryHasASection covers the failure renderDocument exists to
// prevent: a capability category with no section would drop its builtins from
// the catalog entirely.
func TestEveryCategoryHasASection(t *testing.T) {
	described := make(map[string]struct{}, len(categorySections))
	for _, section := range categorySections {
		described[section.category] = struct{}{}
	}

	for _, def := range builtin.Builtins {
		if def.Name == "" {
			continue
		}
		category := builtin.CapabilityCategory(def.Name)
		if _, ok := described[category]; !ok {
			t.Errorf("builtin %q is in capability category %q, which has no section in sections.go",
				def.Name, category)
		}
	}
}

// TestEveryBuiltinAppearsExactlyOnce checks the generated catalog against the
// registry it is generated from — the property a reader actually relies on.
func TestEveryBuiltinAppearsExactlyOnce(t *testing.T) {
	document, err := renderDocument()
	if err != nil {
		t.Fatalf("renderDocument: %v", err)
	}

	counts := make(map[string]int, len(builtin.Builtins))
	for _, line := range strings.Split(document, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		open := strings.IndexByte(line, '(')
		if open < 0 {
			continue
		}
		counts[line[len("| `"):open]]++
	}

	for _, def := range builtin.Builtins {
		if def.Name == "" {
			continue
		}
		switch counts[def.Name] {
		case 1:
			// exactly once, as intended
		case 0:
			t.Errorf("builtin %q is missing from the generated reference", def.Name)
		default:
			t.Errorf("builtin %q appears %d times in the generated reference", def.Name, counts[def.Name])
		}
	}
}

// TestTableCellsAreEscaped pins the escaping that keeps prose from breaking out
// of a table cell — a pipe in a summary would otherwise start a new column.
func TestTableCellsAreEscaped(t *testing.T) {
	got := escapeTableCell("MD5|name|inode\nsecond line ")
	want := `MD5\|name\|inode second line`
	if got != want {
		t.Errorf("escapeTableCell = %q, want %q", got, want)
	}
}
