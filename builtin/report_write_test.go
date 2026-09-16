package builtin

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// Writing a report is where the document stops being a value and becomes
// something somebody else will hold. Two things have to be true at that moment:
// the file is the rendering the program asked for, and the digest handed back is
// a fact about the file rather than about the intention behind it.

func writeTestReport(t *testing.T, report *object.Hash, path string, opts map[string]object.Object) *object.Hash {
	t.Helper()

	args := []object.Object{report, stringObj(path)}
	if opts != nil {
		args = append(args, optsObj(opts))
	}
	value, errObj := unwrapPair(t, ReportWrite(args...))
	if errObj != nil {
		t.Fatalf("report_write failed: %s", errObj.Message)
	}
	return value.(*object.Hash)
}

func fileDigest(t *testing.T, path string) (string, int64) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), int64(len(data))
}

func simpleTestReport(t *testing.T) *object.Hash {
	t.Helper()

	report := newTestReport(t, "Workstation WS-7", map[string]object.Object{
		"generated": stringObj("2026-09-14T00:00:00Z"),
	})
	report = reportCall(t, ReportSection, report, stringObj("Findings"))
	report = reportCall(t, ReportText, report, stringObj("One executable ran from a temporary directory."))
	report = reportCall(t, ReportTable, report, &object.Array{Elements: []object.Object{
		&object.Array{Elements: []object.Object{stringObj("when"), stringObj("what")}},
		&object.Array{Elements: []object.Object{stringObj("09:14"), stringObj("evil.exe")}},
	}})
	return report
}

func TestReportWriteTakesItsFormatFromTheName(t *testing.T) {
	report := simpleTestReport(t)
	dir := t.TempDir()

	for _, tc := range []struct {
		name     string
		format   string
		contains string
	}{
		{"report.html", "html", "<!doctype html>"},
		{"report.htm", "html", "<!doctype html>"},
		{"report.md", "markdown", "# workstation ws-7"},
		{"report.markdown", "markdown", "# workstation ws-7"},
		{"findings.csv", "csv", "when,what"},
	} {
		path := filepath.Join(dir, tc.name)
		result := writeTestReport(t, report, path, nil)

		if got := mustHashStringValue(t, result, "format"); got != tc.format {
			t.Fatalf("%s: format = %q, want %q", tc.name, got, tc.format)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !strings.Contains(strings.ToLower(string(body)), tc.contains) {
			t.Fatalf("%s does not read like %s: %.80q", tc.name, tc.format, string(body))
		}
	}
}

func TestReportWriteFormatOptionOverridesTheName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.html")
	result := writeTestReport(t, simpleTestReport(t), path, map[string]object.Object{
		"format": stringObj("markdown"),
	})

	if got := mustHashStringValue(t, result, "format"); got != "markdown" {
		t.Fatalf("format = %q, want markdown", got)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "<!doctype") {
		t.Fatal("the option was ignored and HTML was written to the .html name")
	}
}

func TestReportWriteRefusesAPathThatSaysNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report")

	_, errObj := unwrapPairNoFatal(ReportWrite(simpleTestReport(t), stringObj(path)))
	if errObj == nil {
		t.Fatal("report_write guessed a format")
	}
	for _, want := range []string{"report_write", ".html", ".csv", "format"} {
		if !strings.Contains(errObj.Message, want) {
			t.Fatalf("the refusal does not mention %q: %s", want, errObj.Message)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a file was created for a format that was never decided")
	}
}

// The claim behind the digest: it describes the bytes on disk. This test takes
// the file's digest independently and insists the two are the same number.
func TestReportWriteDigestDescribesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.html")
	result := writeTestReport(t, simpleTestReport(t), path, nil)

	digest, size := fileDigest(t, path)
	if got := mustHashStringValue(t, result, "sha256"); got != digest {
		t.Fatalf("sha256 = %q, but the file hashes to %q", got, digest)
	}
	if got := mustHashValue(t, result, "bytes").(*object.Integer).Value; got != size {
		t.Fatalf("bytes = %d, but the file is %d bytes", got, size)
	}
	if got := mustHashStringValue(t, result, "path"); got != path {
		t.Fatalf("path = %q, want %q", got, path)
	}
}

// A document with a block nothing renders is refused by report_render, and the
// refusal has to happen before anything is created -- a half-written file left in
// the output directory is a report as far as the next person to open it knows.
func TestReportWriteLeavesNothingBehindWhenItRefuses(t *testing.T) {
	report := newTestReport(t, "Workstation WS-7", nil)
	report = reportCall(t, ReportSection, report, stringObj("Findings"))
	sections := mustHashValue(t, report, "sections").(*object.Array)
	section := sections.Elements[0].(*object.Hash)
	blocks := &object.Array{Elements: []object.Object{
		makeHashObject(map[string]object.Object{"kind": stringObj("chart")}),
	}}
	sections.Elements[0] = hashWith(section, "blocks", blocks)

	path := filepath.Join(t.TempDir(), "report.html")
	_, errObj := unwrapPairNoFatal(ReportWrite(report, stringObj(path)))
	if errObj == nil {
		t.Fatal("report_write rendered a block nothing renders")
	}
	// The refusal names the builtin that was called, not the one that does the
	// rendering underneath it.
	if !strings.HasPrefix(errObj.Message, "report_write:") {
		t.Fatalf("the refusal names the wrong builtin: %s", errObj.Message)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a file was left behind by a write that refused")
	}
}

func TestReportWriteBecomesACaseTimelineEntry(t *testing.T) {
	openTestCase(t, "IR-88", "examiner")
	path := filepath.Join(t.TempDir(), "report.md")
	result := writeTestReport(t, simpleTestReport(t), path, nil)

	entries := manifestArray(t, currentManifest(t), "timeline")
	var found *object.Hash
	for _, element := range entries {
		entry, ok := element.(*object.Hash)
		if !ok {
			continue
		}
		if mustHashStringValue(t, entry, "event") == "report_write" {
			found = entry
		}
	}
	if found == nil {
		t.Fatal("the manifest does not record that a report was written")
	}

	data, ok := mustHashValue(t, found, "data").(*object.Hash)
	if !ok {
		t.Fatal("the timeline entry carries no data")
	}
	if got := mustHashStringValue(t, data, "sha256"); got != mustHashStringValue(t, result, "sha256") {
		t.Fatal("the manifest and the caller were told different digests")
	}
	if got := mustHashStringValue(t, data, "path"); got != path {
		t.Fatalf("the manifest records path %q, want %q", got, path)
	}
	if got := mustHashStringValue(t, data, "format"); got != "markdown" {
		t.Fatalf("the manifest records format %q, want markdown", got)
	}
}

// Reporting does not require a case. An analyst writing a summary of a triage
// run is doing something reasonable, and refusing it would push them back to
// printing to stdout.
func TestReportWriteNeedsNoOpenCase(t *testing.T) {
	resetCustodyForTesting()

	path := filepath.Join(t.TempDir(), "report.md")
	result := writeTestReport(t, simpleTestReport(t), path, nil)
	digest, _ := fileDigest(t, path)
	if got := mustHashStringValue(t, result, "sha256"); got != digest {
		t.Fatalf("sha256 = %q, want %q", got, digest)
	}
}

func TestReportWriteRefusesAnEmptyPath(t *testing.T) {
	_, errObj := unwrapPairNoFatal(ReportWrite(simpleTestReport(t), stringObj("   ")))
	if errObj == nil {
		t.Fatal("report_write accepted an empty path")
	}
	if !strings.Contains(errObj.Message, "must not be empty") {
		t.Fatalf("unhelpful message: %s", errObj.Message)
	}
}

func TestReportWriteCarriesTheRenderOptionsThrough(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fragment.html")
	writeTestReport(t, simpleTestReport(t), path, map[string]object.Object{
		"fragment": &object.Boolean{Value: true},
	})

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(body)), "<!doctype") {
		t.Fatal("fragment:true still wrote the document wrapper")
	}
}
