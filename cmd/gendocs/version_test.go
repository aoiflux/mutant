package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"mutant/global"
)

// The version is stated in one place, global.Version, and repeated in a handful
// of documents a reader treats as authoritative. These tests hold each of them
// to it, so a release cannot ship claiming to be two versions at once -- which
// is how 2.5.0 came to be dated three days before it was tagged, and how
// SECURITY.md came to call 2.4.x current a release later.

const (
	tutorialPath  = "../../docs/TUTORIAL_30_MIN.md"
	securityPath  = "../../SECURITY.md"
	changelogPath = "../../CHANGELOG.md"
	extensionPath = "../../mutant-vscode-extension/package.json"

	// changelogCompareBase is the prefix every release link shares.
	changelogCompareBase = "https://github.com/aoiflux/mutant/compare/"
)

type semver struct{ major, minor, patch int }

func parseSemver(t *testing.T, s string) semver {
	t.Helper()
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		t.Fatalf("%q is not a major.minor.patch version", s)
	}
	var v [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("%q is not a major.minor.patch version: %v", s, err)
		}
		v[i] = n
	}
	return semver{v[0], v[1], v[2]}
}

func readRepoFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

// TestTutorialShowsThisVersion: the tutorial prints a sample `mutant --version`,
// and a reader compares it with what their binary says.
func TestTutorialShowsThisVersion(t *testing.T) {
	doc := readRepoFile(t, tutorialPath)
	stated := regexp.MustCompile(`(?m)^Version: (\S+)$`).FindAllStringSubmatch(doc, -1)
	if len(stated) == 0 {
		t.Fatalf("%s no longer shows a `Version:` line; update this test if the sample moved", tutorialPath)
	}
	for _, m := range stated {
		if m[1] != global.Version {
			t.Errorf("%s shows Version: %s, but global.Version is %s", tutorialPath, m[1], global.Version)
		}
	}
}

// TestSecurityPolicySupportsThisMinor: fixes land on the latest minor only, so
// the supported-versions table names this minor as current and everything
// before it as upgrade.
func TestSecurityPolicySupportsThisMinor(t *testing.T) {
	v := parseSemver(t, global.Version)
	doc := readRepoFile(t, securityPath)

	_, section, found := strings.Cut(doc, "## Supported versions")
	if !found {
		t.Fatalf("%s has no \"## Supported versions\" section", securityPath)
	}
	var rows []string
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "## ") {
			break
		}
		if strings.HasPrefix(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "Version") {
			rows = append(rows, line)
		}
	}
	if len(rows) < 2 {
		t.Fatalf("%s: expected a current row and an upgrade row, found %d rows", securityPath, len(rows))
	}
	cells := func(row string) []string {
		var out []string
		for _, c := range strings.Split(strings.Trim(row, "|"), "|") {
			out = append(out, strings.TrimSpace(c))
		}
		return out
	}
	current, older := cells(rows[0]), cells(rows[1])
	wantCurrent := fmt.Sprintf("%d.%d.x", v.major, v.minor)
	if len(current) < 2 || current[0] != wantCurrent || !strings.Contains(current[1], "current") {
		t.Errorf("%s: first supported-versions row is %q; want %q marked current", securityPath, rows[0], wantCurrent)
	}
	if v.minor > 0 {
		wantOlder := fmt.Sprintf("%d.%d.x and earlier", v.major, v.minor-1)
		if len(older) < 2 || older[0] != wantOlder || !strings.Contains(older[1], "upgrade") {
			t.Errorf("%s: second supported-versions row is %q; want %q marked upgrade", securityPath, rows[1], wantOlder)
		}
	}
}

var (
	changelogHeading = regexp.MustCompile(`(?m)^## \[([^\]]+)\](.*)$`)
	changelogDate    = regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)
	changelogLink    = regexp.MustCompile(`(?m)^\[([^\]]+)\]: (\S+)$`)
)

// TestChangelogLeadsWithThisVersion: [Unreleased] first, then global.Version,
// release dates descending, and compare links that match the headings. The top
// release may be undated while it waits for its tag; the release gate checks
// the date against the tag once the tag exists.
func TestChangelogLeadsWithThisVersion(t *testing.T) {
	doc := readRepoFile(t, changelogPath)
	headings := changelogHeading.FindAllStringSubmatch(doc, -1)
	if len(headings) < 3 {
		t.Fatalf("%s: expected [Unreleased] and at least two releases, found %d headings", changelogPath, len(headings))
	}
	if headings[0][1] != "Unreleased" {
		t.Errorf("%s: the first heading is [%s]; want [Unreleased]", changelogPath, headings[0][1])
	}
	if headings[1][1] != global.Version {
		t.Errorf("%s: the first release heading is [%s]; global.Version is %s", changelogPath, headings[1][1], global.Version)
	}

	var previous time.Time
	for i, h := range headings[1:] {
		date := changelogDate.FindString(h[2])
		if date == "" {
			if i == 0 {
				continue // the release awaiting its tag
			}
			t.Errorf("%s: [%s] has no date", changelogPath, h[1])
			continue
		}
		when, err := time.Parse(time.DateOnly, date)
		if err != nil {
			t.Errorf("%s: [%s] has an unreadable date %q", changelogPath, h[1], date)
			continue
		}
		if !previous.IsZero() && when.After(previous) {
			t.Errorf("%s: [%s] (%s) is dated after the release above it", changelogPath, h[1], date)
		}
		previous = when
	}

	links := map[string]string{}
	for _, m := range changelogLink.FindAllStringSubmatch(doc, -1) {
		links[m[1]] = m[2]
	}
	prior := headings[2][1]
	wants := map[string]string{
		"Unreleased":   changelogCompareBase + "v" + global.Version + "...HEAD",
		global.Version: changelogCompareBase + "v" + prior + "...v" + global.Version,
	}
	for name, want := range wants {
		if got := links[name]; got != want {
			t.Errorf("%s: [%s] links to %q; want %q", changelogPath, name, got, want)
		}
	}
}

// TestExtensionNamesThisLanguageVersion: the extension versions on its own
// line, so it records separately which language release it teaches.
func TestExtensionNamesThisLanguageVersion(t *testing.T) {
	var manifest struct {
		Version               string `json:"version"`
		MutantLanguageVersion string `json:"mutantLanguageVersion"`
	}
	if err := json.Unmarshal([]byte(readRepoFile(t, extensionPath)), &manifest); err != nil {
		t.Fatalf("reading %s: %v", extensionPath, err)
	}
	if manifest.MutantLanguageVersion != global.Version {
		t.Errorf("%s: mutantLanguageVersion is %q; global.Version is %s", extensionPath, manifest.MutantLanguageVersion, global.Version)
	}
	if manifest.Version == "" {
		t.Errorf("%s has no version of its own", extensionPath)
	}
}
