package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"mutant/builtin"
)

// The generated documents cannot drift: gendocs writes CAPABILITY_REFERENCE.md
// and the grammar, and two tests fail when either is behind. The prose around
// them had no such check, and it drifted the same way the grammar did -- four
// documents still telling a reader the standard library holds 459 builtins
// across 34 categories, a count three releases old, found 2026-09-16 while
// registering the sigma_* family.
//
// It is the same failure as ED-1 in a different file type: a hand-written claim
// about the registry, with nothing that fails when the registry moves. So it
// gets the same answer.

// proseCountPaths are the documents that describe the standard library as it is
// now. A count in any of them is a claim about this build.
var proseCountPaths = []string{
	"README.md",
	"docs/COOKBOOK.md",
	"docs/WHAT_IS_MUTANT.md",
	"docs/WASM_REPL_REFERENCE.md",
	"docs/TUTORIAL_30_MIN.md",
	"docs/QUICK_REFERENCE.md",
	"docs/COMPARISON.md",
	"docs/STRUCTURED_DATA.md",
	"docs/INTERCHANGE_SCHEMAS.md",
	"docs/DETECTION_RULES.md",
	"docs/MUTANT_LANGUAGE_REFERENCE.md",
	"docs/EXECUTION_MODES.md",
}

// Deliberately not listed, and why: CHANGELOG.md and CONTRIBUTING.md record
// what was true at a past release, and the roadmap under plans/ records what a
// measurement found on a given day. A count in those is history, and correcting
// history would be the untruth. CAPABILITY_REFERENCE.md is generated and has
// its own test.

var (
	builtinCountPattern  = regexp.MustCompile(`(\d+)\s+builtins`)
	categoryCountPattern = regexp.MustCompile(`(\d+)\s+categories`)
	runnablePattern      = regexp.MustCompile(`(\d+)\s+runnable programs`)
)

// TestProseCountsMatchTheRegistry is the drift gate. A document that says how
// many builtins there are has to say the number there are.
func TestProseCountsMatchTheRegistry(t *testing.T) {
	wantBuiltins := len(builtin.Builtins)
	wantCategories := len(categorySections)

	for _, path := range proseCountPaths {
		full := filepath.FromSlash("../../" + path)
		document, err := os.ReadFile(full)
		if err != nil {
			if os.IsNotExist(err) {
				t.Errorf("%s is listed here but does not exist; remove it from proseCountPaths", path)
				continue
			}
			t.Fatalf("reading %s: %v", path, err)
		}

		text := string(document)
		checkCount(t, path, text, builtinCountPattern, wantBuiltins, "builtins")
		checkCount(t, path, text, categoryCountPattern, wantCategories, "categories")
	}
}

// checkCount searches the whole document rather than line by line, because
// these documents are hard-wrapped and "469 builtins across 35\ncategories"
// would otherwise walk straight past a check written for one line at a time.
// Newlines become spaces, which keeps every byte offset where it was, so the
// match can still be reported at the line it is on.
func checkCount(t *testing.T, path, text string, pattern *regexp.Regexp, want int, noun string) {
	t.Helper()

	flat := strings.ReplaceAll(text, "\n", " ")
	for _, span := range pattern.FindAllStringSubmatchIndex(flat, -1) {
		got, err := strconv.Atoi(flat[span[2]:span[3]])
		if err != nil {
			continue
		}
		if got == want {
			continue
		}
		line := strings.Count(text[:span[0]], "\n") + 1
		t.Errorf("%s:%d says %d %s; the registry has %d.\n  claim: %s",
			path, line, got, noun, want, strings.TrimSpace(flat[span[0]:span[1]]))
	}
}

// TestProseExampleCountsMatchTheTree is the same check for the other number
// these documents quote, and it drifted too: the examples directory had grown
// by twelve programs since anyone last counted it.
func TestProseExampleCountsMatchTheTree(t *testing.T) {
	want := 0
	root := filepath.FromSlash("../../examples")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".mut") {
			want++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking examples: %v", err)
	}
	if want == 0 {
		t.Fatalf("walked examples/ and found no .mut files")
	}

	for _, path := range proseCountPaths {
		document, err := os.ReadFile(filepath.FromSlash("../../" + path))
		if err != nil {
			continue // reported by the test above
		}
		checkCount(t, path, string(document), runnablePattern, want, "runnable programs")
	}
}

// categoryTableRow matches one row of the category index in
// docs/MUTANT_LANGUAGE_REFERENCE.md, which is written by hand and links into
// the generated reference by an anchor that carries the count in it.
var categoryTableRow = regexp.MustCompile(
	`\| \[([^\]]+)\]\(CAPABILITY_REFERENCE\.md#([a-z0-9-]+)\) \| (\d+) \| `)

// TestCategoryIndexMatchesTheRegistry guards the per-category table.
//
// The two totals above it were guarded and the thirty-nine rows under it were
// not, which is how the table came to be missing an entire category. On
// 2026-09-22 it listed 38 rows totalling 493 against a registry of 39 and 632:
// no row at all for the forensic ledger -- the whole of Phase 4 -- and five
// counts stale enough that their anchors pointed at headings that no longer
// existed. A reader following [Filesystem forensics](...#filesystem-forensics-37)
// landed nowhere, because the heading had said 115 for some time.
//
// The count is in the anchor as well as in the cell, so both are checked. An
// anchor is the half that fails silently: a wrong number in a cell is visibly
// wrong, and a wrong number in a link is a dead link somebody else discovers.
func TestCategoryIndexMatchesTheRegistry(t *testing.T) {
	const path = "docs/MUTANT_LANGUAGE_REFERENCE.md"
	document, err := os.ReadFile(filepath.FromSlash("../../" + path))
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	// The same grouping renderDocument does, so the table is checked against
	// the registry rather than against the generated file it links into.
	byCategory := make(map[string]int, len(categorySections))
	for _, b := range builtin.Builtins {
		if b.Name == "" {
			continue
		}
		byCategory[builtin.CapabilityCategory(b.Name)]++
	}

	listed := make(map[string]bool, len(categorySections))
	for _, match := range categoryTableRow.FindAllStringSubmatch(string(document), -1) {
		heading, gotAnchor, gotCount := match[1], match[2], match[3]

		var section *categorySection
		for i := range categorySections {
			if strings.EqualFold(categorySections[i].heading, heading) {
				section = &categorySections[i]
				break
			}
		}
		if section == nil {
			t.Errorf("%s: the category index has a row for %q, which is not a section in "+
				"cmd/gendocs/sections.go", path, heading)
			continue
		}
		listed[section.category] = true

		want := byCategory[section.category]
		if gotCount != strconv.Itoa(want) {
			t.Errorf("%s: the category index says %s holds %s builtins; the registry has %d",
				path, heading, gotCount, want)
		}
		if wantAnchor := headingAnchor(section.heading, want); gotAnchor != wantAnchor {
			t.Errorf("%s: the %s row links to #%s, and the reference's heading is #%s. "+
				"The link is dead", path, heading, gotAnchor, wantAnchor)
		}
	}

	for _, section := range categorySections {
		if !listed[section.category] {
			t.Errorf("%s: the category index has no row for %q (%d builtins), so nothing in "+
				"the reference points a reader at it", path, section.heading,
				byCategory[section.category])
		}
	}
}

// headingAnchor is GitHub's slug for a generated "## Heading (N)" line:
// lowercased, anything that is not a letter, digit, space or hyphen dropped,
// spaces to hyphens. The parenthesised count becomes a trailing -N, which is
// why a stale count breaks the link rather than just reading wrong.
func headingAnchor(heading string, count int) string {
	var b strings.Builder
	for _, r := range strings.ToLower(heading) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	return fmt.Sprintf("%s-%d", b.String(), count)
}
