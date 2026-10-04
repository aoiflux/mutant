package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// An advisory is a promise to a reader who cannot check it: that an
// identifier means one issue, that the identifier is the same everywhere it
// is written, and that something in this repository holds the fix in place.
// These tests check each of those, because the alternative is a page that
// drifts quietly away from the tree while looking authoritative.

const (
	advisoryDir      = "docs/advisories"
	advisoryIndex    = "docs/advisories/README.md"
	advisoryTestNote = "SECURITY.md calls the test an advisory names its fixture"
)

var (
	advisoryID   = regexp.MustCompile(`\bMVF-(\d{4})-(\d{4})\b`)
	advisoryRow  = regexp.MustCompile(`^\|\s*(?:\[)?(MVF-\d{4}-\d{4})`)
	advisoryTest = regexp.MustCompile("`([A-Za-z0-9_./-]+_test\\.go)`")
)

// indexedAdvisories reads the identifiers the index lists as published, in the
// order its table gives them.
func indexedAdvisories(t *testing.T) []string {
	t.Helper()
	var ids []string
	for _, line := range proseLines(t, advisoryIndex) {
		if m := advisoryRow.FindStringSubmatch(strings.TrimSpace(line.text)); m != nil {
			ids = append(ids, m[1])
		}
	}
	if len(ids) == 0 {
		t.Fatalf("%s lists no advisories; the scanner or the table has changed shape", advisoryIndex)
	}
	return ids
}

// TestAdvisorySerialsAreWholeAndUnique holds the index to the one rule that
// makes an identifier citable: it names exactly one issue, for good. A serial
// used twice, or the table reordered so a reader cannot tell which row a
// citation meant, is the failure this catches.
func TestAdvisorySerialsAreWholeAndUnique(t *testing.T) {
	ids := indexedAdvisories(t)

	seen := map[string]int{}
	serials := map[int]bool{}
	for i, id := range ids {
		if first, dup := seen[id]; dup {
			t.Errorf("%s is listed twice, at rows %d and %d; an identifier names one issue", id, first+1, i+1)
			continue
		}
		seen[id] = i

		m := advisoryID.FindStringSubmatch(id)
		if _, err := strconv.Atoi(m[1]); err != nil {
			t.Errorf("%s has no four-digit year", id)
		}
		serial, err := strconv.Atoi(m[2])
		if err != nil || serial < 1 {
			t.Errorf("%s has no positive four-digit serial", id)
			continue
		}
		serials[serial] = true
	}

	// Allocated one at a time, so the published set runs from 1 with no hole.
	// A hole would mean an identifier was assigned and then lost, which is the
	// one thing a register must not do.
	for want := 1; want <= len(serials); want++ {
		if !serials[want] {
			t.Errorf("serial %04d is missing although %d advisories are listed: an identifier was assigned and is not accounted for",
				want, len(serials))
		}
	}
}

// TestEveryAdvisoryIsInTheChangelogAndBack keeps the two places an identifier
// is written from drifting apart. The changelog is what a reader of the
// release notes sees; the index is what a reader following a citation sees.
// One naming an advisory the other does not know about means one of them is
// wrong, and there is no way for the reader to tell which.
func TestEveryAdvisoryIsInTheChangelogAndBack(t *testing.T) {
	indexed := map[string]bool{}
	for _, id := range indexedAdvisories(t) {
		indexed[id] = true
	}

	changelog := readRepoFile(t, changelogPath)
	inChangelog := map[string]bool{}
	for _, m := range advisoryID.FindAllString(changelog, -1) {
		inChangelog[m] = true
	}

	for _, id := range sortedKeys(indexed) {
		if !inChangelog[id] {
			t.Errorf("%s is published in %s but named nowhere in CHANGELOG.md, so the release notes do not disclose it",
				id, advisoryIndex)
		}
	}
	for _, id := range sortedKeys(inChangelog) {
		if !indexed[id] {
			t.Errorf("CHANGELOG.md cites %s, which %s does not list: a citation with nothing behind it",
				id, advisoryIndex)
		}
	}
}

// TestEveryAdvisoryPageIsListedAndNamesItself catches the page whose file name
// and heading disagree, and the page nothing links to.
func TestEveryAdvisoryPageIsListedAndNamesItself(t *testing.T) {
	indexed := map[string]bool{}
	for _, id := range indexedAdvisories(t) {
		indexed[id] = true
	}

	entries, err := os.ReadDir(filepath.Join(repoRoot, filepath.FromSlash(advisoryDir)))
	if err != nil {
		t.Fatalf("reading %s: %v", advisoryDir, err)
	}
	pages := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "MVF-") || !strings.HasSuffix(name, ".md") {
			continue
		}
		pages++
		id := strings.TrimSuffix(name, ".md")
		if !advisoryID.MatchString(id) {
			t.Errorf("%s/%s is not named for an identifier", advisoryDir, name)
			continue
		}
		if !indexed[id] {
			t.Errorf("%s/%s exists but %s does not list %s", advisoryDir, name, advisoryIndex, id)
		}
		raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(advisoryDir), name))
		if err != nil {
			t.Errorf("reading %s/%s: %v", advisoryDir, name, err)
			continue
		}
		if !strings.Contains(string(raw), id) {
			t.Errorf("%s/%s never names %s, so a reader cannot tell the page from its neighbours", advisoryDir, name, id)
		}
	}
	if pages == 0 {
		t.Fatalf("no advisory pages found in %s; the scanner is broken", advisoryDir)
	}
}

// TestEveryAdvisoryPageNamesAFixtureThatExists is the half of the scheme that
// is not bookkeeping. A published advisory has to name the test that fails on
// the unfixed code, and that test has to be in the tree -- otherwise the fix
// has nothing holding it and the next refactor can quietly undo it.
func TestEveryAdvisoryPageNamesAFixtureThatExists(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join(repoRoot, filepath.FromSlash(advisoryDir)))
	if err != nil {
		t.Fatalf("reading %s: %v", advisoryDir, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "MVF-") || !strings.HasSuffix(name, ".md") {
			continue
		}
		rel := advisoryDir + "/" + name

		var fixtures []string
		for _, line := range proseLines(t, rel) {
			for _, m := range advisoryTest.FindAllStringSubmatch(line.text, -1) {
				fixtures = append(fixtures, m[1])
			}
		}
		sort.Strings(fixtures)

		if len(fixtures) == 0 {
			t.Errorf("%s names no test file: %s, and a fix with no test is not published", rel, advisoryTestNote)
			continue
		}
		for _, f := range fixtures {
			if _, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(f))); err != nil {
				t.Errorf("%s names %s as its fixture, which this repository does not have", rel, f)
			}
		}
	}
}
