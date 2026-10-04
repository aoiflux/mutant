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
	advisoryDir        = "docs/advisories"
	advisoryIndex      = "docs/advisories/README.md"
	advisoryTestNote   = "SECURITY.md calls the test an advisory names its fixture"
	advisoryCreditNote = "SECURITY.md promises reporters are credited in the advisory AND in CHANGELOG.md"
)

var (
	advisoryID       = regexp.MustCompile(`\bMVF-(\d{4})-(\d{4})\b`)
	advisoryRow      = regexp.MustCompile(`^\|\s*(?:\[)?(MVF-\d{4}-\d{4})`)
	advisoryTest     = regexp.MustCompile("`([A-Za-z0-9_./-]+_test\\.go)`")
	advisoryReported = regexp.MustCompile(`^\|\s*\*\*Reported\*\*\s*\|\s*(.*?)\s*\|\s*$`)
)

// indexedAdvisories reads the identifiers the index lists as published, in the
// order its table gives them.
//
// It reads the "Published" section alone. It used to read every table row in
// the file, which was the same thing while that was the only table keyed by an
// identifier; the severity-vector table is a second, and a whole-file scan sees
// each identifier twice and reports every one as a serial used twice. The
// section boundary is what the helper meant all along -- its own first line
// says "lists as published" -- so this is that sentence enforced rather than a
// new rule.
func indexedAdvisories(t *testing.T) []string {
	t.Helper()
	var ids []string
	inPublished := false
	for _, line := range proseLines(t, advisoryIndex) {
		if trimmed := strings.TrimSpace(line.text); strings.HasPrefix(trimmed, "## ") {
			inPublished = trimmed == "## Published"
			continue
		}
		if !inPublished {
			continue
		}
		if m := advisoryRow.FindStringSubmatch(strings.TrimSpace(line.text)); m != nil {
			ids = append(ids, m[1])
		}
	}
	if len(ids) == 0 {
		t.Fatalf("%s lists no advisories under '## Published'; the scanner or the table has changed shape",
			advisoryIndex)
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

// A severity vector is written twice: in the register, which has a row for
// every identifier whether or not it has a page of its own, and in the header
// table of a page that exists. Two copies of a number drift, and a vector that
// disagrees with itself is worse than one nobody published, because a reader
// cannot tell which copy was revised. The two tests below are what stops that,
// and they also hold a vector to its own grammar: a transposed metric is a
// typo nobody would notice by reading.

var (
	// The register's rows: identifier, possibly linked, then the internal row,
	// then the two backticked vectors.
	vectorRow = regexp.MustCompile(
		"^\\|\\s*(?:\\[)?(MVF-\\d{4}-\\d{4})(?:\\]\\([^)]*\\))?\\s*\\|[^|]*\\|\\s*" +
			"`([^`]+)`\\s*\\|\\s*`([^`]+)`\\s*\\|")
	// A page's own header-table rows.
	pageVector = regexp.MustCompile(`^\|\s*CVSS:(3\.1|4\.0)\s*\|\s*(\S+)\s*\|`)

	cvss31 = regexp.MustCompile(
		`^CVSS:3\.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]$`)
	cvss40 = regexp.MustCompile(
		`^CVSS:4\.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]` +
			`/VC:[NLH]/VI:[NLH]/VA:[NLH]/SC:[NLH]/SI:[NLH]/SA:[NLH]$`)
)

// advisoryVectors reads the register's severity-vector table as
// identifier -> {CVSS:3.1, CVSS:4.0}. It reads that section alone: the
// published table above it starts its rows with an identifier too, and a
// scanner that took the whole file would match those and report every vector
// as missing.
func advisoryVectors(t *testing.T) map[string][2]string {
	t.Helper()
	out := map[string][2]string{}
	inSection := false
	for _, line := range proseLines(t, advisoryIndex) {
		if strings.HasPrefix(strings.TrimSpace(line.text), "## ") {
			inSection = strings.TrimSpace(line.text) == "## Severity vectors"
			continue
		}
		if !inSection {
			continue
		}
		if m := vectorRow.FindStringSubmatch(strings.TrimSpace(line.text)); m != nil {
			if _, seen := out[m[1]]; seen {
				t.Errorf("%s:%d lists %s in the severity-vector table twice",
					advisoryIndex, line.n, m[1])
			}
			out[m[1]] = [2]string{m[2], m[3]}
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s has no severity-vector table; the section or the scanner has changed shape",
			advisoryIndex)
	}
	return out
}

// TestEveryAdvisoryCarriesBothVectors holds the register's two tables to each
// other in both directions. An identifier with no vector is an advisory nobody
// scored; a vector with no identifier is a row left behind by a renumbering.
func TestEveryAdvisoryCarriesBothVectors(t *testing.T) {
	vectors := advisoryVectors(t)
	published := indexedAdvisories(t)

	for _, id := range published {
		v, ok := vectors[id]
		if !ok {
			t.Errorf("%s is published but the severity-vector table has no row for it", id)
			continue
		}
		if !cvss31.MatchString(v[0]) {
			t.Errorf("%s: %q is not a CVSS:3.1 base vector", id, v[0])
		}
		if !cvss40.MatchString(v[1]) {
			t.Errorf("%s: %q is not a CVSS:4.0 base vector", id, v[1])
		}
	}

	listed := map[string]bool{}
	for _, id := range published {
		listed[id] = true
	}
	for id := range vectors {
		if !listed[id] {
			t.Errorf("the severity-vector table scores %s, which the published table does not list", id)
		}
	}
}

// TestAdvisoryPageVectorsMatchTheIndex is the half that matters once a page
// exists. A page repeats its own two vectors so a reader who opens it alone
// sees them, and this is what keeps that copy honest.
func TestAdvisoryPageVectorsMatchTheIndex(t *testing.T) {
	vectors := advisoryVectors(t)
	entries, err := os.ReadDir(filepath.Join(repoRoot, filepath.FromSlash(advisoryDir)))
	if err != nil {
		t.Fatalf("reading %s: %v", advisoryDir, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "MVF-") || !strings.HasSuffix(name, ".md") {
			continue
		}
		id := strings.TrimSuffix(name, ".md")
		want, ok := vectors[id]
		if !ok {
			continue // TestEveryAdvisoryCarriesBothVectors reports this
		}
		got := map[string]string{}
		for _, line := range proseLines(t, advisoryDir+"/"+name) {
			if m := pageVector.FindStringSubmatch(strings.TrimSpace(line.text)); m != nil {
				got[m[1]] = m[2]
			}
		}
		for version, wanted := range map[string]string{"3.1": want[0], "4.0": want[1]} {
			switch have := got[version]; {
			case have == "":
				t.Errorf("%s/%s has no CVSS:%s row, although the register scores it",
					advisoryDir, name, version)
			case have != wanted:
				t.Errorf("%s/%s says CVSS:%s is %q and the register says %q",
					advisoryDir, name, version, have, wanted)
			}
		}
	}
}

// TestEveryPublishedAdvisoryHasAPage is the other half of the no-gaps rule, and
// it is the owner's, recorded 2026-10-05: "We cannot have disconnected MVF IDs,
// as in MVF-2026-0001 and MVF-2026-0007 exist but others in between dont."
//
// TestAdvisorySerialsAreWholeAndUnique already refuses a hole in the SERIALS.
// This refuses a hole in the PAGES, which is the gap a reader actually walks
// into: an identifier listed in the register, cited from the changelog, and
// linked from nowhere, so following it means guessing whether a page was owed
// and never written or never owed at all. The register's own text used to say
// gaps carry no information. They do: they say somebody stopped halfway.
func TestEveryPublishedAdvisoryHasAPage(t *testing.T) {
	for _, id := range indexedAdvisories(t) {
		page := filepath.Join(repoRoot, filepath.FromSlash(advisoryDir), id+".md")
		if _, err := os.Stat(page); err != nil {
			t.Errorf("%s is listed in %s but has no page at %s/%s.md: an identifier a reader cannot follow",
				id, advisoryIndex, advisoryDir, id)
		}
	}
}

// The advisory scheme makes exactly one promise to somebody outside this
// project, and SECURITY.md is where it is written: "Reporters are credited in
// the advisory and in CHANGELOG.md unless you ask not to be." Two files,
// edited weeks apart, by hand, with nothing joining them.
//
// That promise has already been half-kept once. MVF-2026-0001's fix landed on
// 3 October and the reporter's consent to be named arrived on the 4th, so the
// credit went into the advisory and the changelog named nobody for two days.
// Nothing in the tree noticed; a note outside it held the canonical wording and
// declared that the wording must be identical everywhere, which worked about as
// well as asking politely -- one copy had quietly drifted to a thinner draft.
//
// So the promise is checked against the two files SECURITY.md names, and the
// note goes back to being a note.
//
// Word sequence rather than bytes: an advisory page wraps at eighty columns and
// the changelog wraps inside a list item, so the same sentence cannot be
// byte-identical in both files. Collapsing whitespace compares what a reader
// reads.
func TestAnExternalReporterIsCreditedWhereSecurityMdPromises(t *testing.T) {
	changelog := readingAsAReaderDoes(readRepoFile(t, changelogPath))
	external := 0

	for _, id := range indexedAdvisories(t) {
		reported, credit := advisoryCredit(t, id)
		switch {
		case reported == "":
			t.Errorf("%s's page has no **Reported** row in its header table, so nothing here can say whether a credit is owed",
				id)
		case credit == "":
			t.Errorf("%s's page has no '## Credit' section: %s", id, advisoryCreditNote)
		case !strings.HasPrefix(reported, "externally"):
			// The forward check below only looks at pages whose header says
			// the row came from outside. A credit added to an internal-looking
			// page is therefore invisible to it, and to a reader scanning the
			// header tables -- so that combination is the failure, not an
			// oversight to be tolerated.
			if strings.Contains(credit, "Reported by") {
				t.Errorf("%s credits an outside reporter but its **Reported** cell reads %q; one of the two is wrong, and while they disagree the credit is invisible\n  the page says: %s",
					id, reported, credit)
			}
		default:
			external++
			if !strings.Contains(changelog, credit) {
				t.Errorf("%s was reported from outside and its page credits the reporter, but CHANGELOG.md does not carry that credit: %s\n  the page says: %s",
					id, advisoryCreditNote, credit)
			}
		}
	}

	if external == 0 {
		t.Fatalf("no published advisory has a **Reported** cell beginning 'externally', so this test checked nothing: either the header table changed shape or an external credit was dropped")
	}
}

// advisoryCredit reads a page's Reported cell and the first paragraph of its
// Credit section.
//
// The first paragraph is the credit. What follows it is commentary, and the
// distinction is load-bearing: MVF-2026-0001's Credit section goes on to record
// the severity the row was first given and why that was wrong, which is part of
// the advisory's honesty and no part of anybody's credit.
func advisoryCredit(t *testing.T, id string) (reported, credit string) {
	t.Helper()
	inCredit, started := false, false
	for _, line := range proseLines(t, advisoryDir+"/"+id+".md") {
		trimmed := strings.TrimSpace(line.text)
		if m := advisoryReported.FindStringSubmatch(trimmed); m != nil {
			reported = m[1]
		}
		if strings.HasPrefix(trimmed, "## ") {
			if inCredit {
				break
			}
			inCredit = trimmed == "## Credit"
			continue
		}
		if !inCredit {
			continue
		}
		if trimmed == "" {
			if started {
				break
			}
			continue
		}
		started = true
		credit += " " + trimmed
	}
	return reported, readingAsAReaderDoes(credit)
}

// readingAsAReaderDoes collapses every run of whitespace to a single space, so
// two copies of one sentence wrapped to different widths compare equal.
func readingAsAReaderDoes(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
