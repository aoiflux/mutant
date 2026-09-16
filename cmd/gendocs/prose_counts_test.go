package main

import (
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
