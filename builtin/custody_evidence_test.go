package builtin

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mutant/object"
)

// writeTestImage writes a file that raw_open will accept and returns its path
// and sha256, so a test can assert the manifest recorded the real digest rather
// than a digest of its own invention.
func writeTestImage(t *testing.T, name string, size int) (string, string) {
	t.Helper()

	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("writing the test image: %v", err)
	}

	sum := sha256.Sum256(payload)

	// Returned as custody will record it, not as the test typed it. Windows
	// hands back an 8.3 short path for a TEMP under a username longer than
	// eight characters -- `C:\Users\RUNNER~1\...` -- and custodyResolvePath
	// expands it, so a test comparing against the spelling it passed in failed
	// on exactly that kind of host and passed on every other one. The two
	// spellings naming one file is the point, and
	// TestTwoSpellingsOfOneFileAreOneEvidenceEntry is what pins it.
	return custodyResolvePath(path), hex.EncodeToString(sum[:])
}

// The manifest keys evidence on the resolved path, so a file reached by two
// names is one exhibit rather than two. Nothing pinned that until a Windows
// runner found it the hard way: a short path and a long path for one file were
// the same file, and a test that assumed otherwise failed there and nowhere
// else.
func TestTwoSpellingsOfOneFileAreOneEvidenceEntry(t *testing.T) {
	useTestKeyStore(t)

	direct, _ := writeTestImage(t, "carved.bin", 1024)
	openTestCase(t, "IR-2", "examiner", makeHashObject(map[string]object.Object{
		"hash": stringObj("none"),
	}))

	// A second spelling of the same file: down into a real directory and back
	// out. A traversal rather than a symlink, because creating a symlink on
	// Windows needs a privilege the test cannot assume it has -- and the
	// directory is really created, so filepath.EvalSymlinks resolves the path
	// rather than failing and handing the work to the Abs fallback. Built by
	// concatenation because filepath.Join cleans the "sub/.." straight back out.
	dir := filepath.Dir(direct)
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatalf("creating the directory to traverse: %v", err)
	}
	sep := string(filepath.Separator)
	indirect := dir + sep + "sub" + sep + ".." + sep + filepath.Base(direct)
	if indirect == direct {
		t.Fatalf("the two spellings came out identical: %q", direct)
	}

	for _, spelling := range []string{direct, indirect} {
		if _, errObj := unwrapPair(t, CaseEvidence(stringObj(spelling))); errObj != nil {
			t.Fatalf("case_evidence(%q) failed: %s", spelling, errObj.Message)
		}
	}

	entries := evidenceEntries(t, currentManifest(t))
	if len(entries) != 1 {
		t.Fatalf("two names for one file made %d evidence entries, want 1", len(entries))
	}
	if got := mustHashStringValue(t, entries[0], "path"); got != direct {
		t.Fatalf("the entry records %q, want the resolved %q", got, direct)
	}
}

func evidenceEntries(t *testing.T, manifest *object.Hash) []*object.Hash {
	t.Helper()

	elements := manifestArray(t, manifest, "evidence")
	out := make([]*object.Hash, 0, len(elements))
	for _, element := range elements {
		entry, ok := element.(*object.Hash)
		if !ok {
			t.Fatalf("evidence entry is %T, want HASH", element)
		}
		out = append(out, entry)
	}
	return out
}

func openRawHandle(t *testing.T, path string) string {
	t.Helper()

	value, errObj := unwrapPair(t, RAWOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("raw_open failed: %s", errObj.Message)
	}
	return mustHashStringValue(t, value.(*object.Hash), "handle")
}

func TestOpeningEvidenceRecordsItsSource(t *testing.T) {
	path, digest := writeTestImage(t, "disk.dd", 4096)
	openTestCase(t, "IR-1", "examiner",
		makeHashObject(map[string]object.Object{"hash": stringObj("sha256")}))

	handle := openRawHandle(t, path)
	t.Cleanup(func() { RAWClose(stringObj(handle)) })

	entries := evidenceEntries(t, currentManifest(t))
	if len(entries) != 1 {
		t.Fatalf("manifest holds %d evidence entries, want 1", len(entries))
	}
	entry := entries[0]

	if got := mustHashStringValue(t, entry, "path"); !strings.HasSuffix(got, "disk.dd") {
		t.Fatalf("path = %q", got)
	}
	if got := mustHashIntValue(t, entry, "size"); got != 4096 {
		t.Fatalf("size = %d, want 4096", got)
	}
	if got := mustHashStringValue(t, entry, "hash"); got != digest {
		t.Fatalf("hash = %q, want the file's real sha256 %q", got, digest)
	}
	if got := mustHashStringValue(t, entry, "hash_algo"); got != "sha256" {
		t.Fatalf("hash_algo = %q", got)
	}

	opens, ok := mustHashValue(t, entry, "opens").(*object.Array)
	if !ok || len(opens.Elements) != 1 {
		t.Fatalf("opens did not record the single raw_open")
	}
	if got := mustHashStringValue(t, opens.Elements[0].(*object.Hash), "builtin"); got != "raw_open" {
		t.Fatalf("opens[0].builtin = %q", got)
	}
}

// "Every builtin that touched it" is the claim the manifest makes, and this is
// the check on it. The counts are aggregated, because a program that reads a
// hundred thousand files must not produce a hundred-thousand-line manifest.
func TestTouchesAreCountedPerBuiltin(t *testing.T) {
	path, _ := writeTestImage(t, "disk.dd", 2048)
	openTestCase(t, "IR-1", "examiner")

	handle := openRawHandle(t, path)

	for i := 0; i < 3; i++ {
		if _, errObj := unwrapPair(t, RAWReadAt(stringObj(handle), intObj(0), intObj(16))); errObj != nil {
			t.Fatalf("raw_read_at failed: %s", errObj.Message)
		}
	}
	if _, errObj := unwrapPair(t, RAWMetadata(stringObj(handle))); errObj != nil {
		t.Fatalf("raw_metadata failed: %s", errObj.Message)
	}

	touches, ok := mustHashValue(t, evidenceEntries(t, currentManifest(t))[0], "touches").(*object.Array)
	if !ok {
		t.Fatal("touches is not an ARRAY")
	}
	counted := map[string]int64{}
	for _, element := range touches.Elements {
		entry := element.(*object.Hash)
		counted[mustHashStringValue(t, entry, "builtin")] = mustHashIntValue(t, entry, "count")
	}

	if counted["raw_read_at"] != 3 {
		t.Fatalf("raw_read_at counted %d times, want 3", counted["raw_read_at"])
	}
	if counted["raw_metadata"] != 1 {
		t.Fatalf("raw_metadata counted %d times, want 1", counted["raw_metadata"])
	}
	if len(counted) != 2 {
		t.Fatalf("touches recorded %d builtins, want 2: %v", len(counted), counted)
	}

	// Letting go of the evidence is part of the record too: it closes the window
	// in which the program held the source open.
	if _, errObj := unwrapPair(t, RAWClose(stringObj(handle))); errObj != nil {
		t.Fatalf("raw_close failed: %s", errObj.Message)
	}
	touches = mustHashValue(t, evidenceEntries(t, currentManifest(t))[0], "touches").(*object.Array)
	closed := false
	for _, element := range touches.Elements {
		if mustHashStringValue(t, element.(*object.Hash), "builtin") == "raw_close" {
			closed = true
		}
	}
	if !closed {
		t.Fatal("raw_close is not in the touch record")
	}
}

// Two handles over one file are one piece of evidence with two opens. Anything
// else and a manifest's evidence count means nothing.
func TestTwoHandlesOverOneFileAreOneEvidenceEntry(t *testing.T) {
	path, _ := writeTestImage(t, "disk.dd", 512)
	openTestCase(t, "IR-1", "examiner")

	first := openRawHandle(t, path)
	second := openRawHandle(t, path)
	t.Cleanup(func() {
		RAWClose(stringObj(first))
		RAWClose(stringObj(second))
	})

	entries := evidenceEntries(t, currentManifest(t))
	if len(entries) != 1 {
		t.Fatalf("manifest holds %d evidence entries, want 1", len(entries))
	}
	opens := mustHashValue(t, entries[0], "opens").(*object.Array)
	if len(opens.Elements) != 2 {
		t.Fatalf("opens holds %d entries, want 2", len(opens.Elements))
	}
}

// A handle opened before the case was is not in the record, and the manifest
// must not claim custody of something it never saw opened.
func TestAHandleOlderThanTheCaseIsNotRecorded(t *testing.T) {
	path, _ := writeTestImage(t, "disk.dd", 512)
	resetCustodyForTesting()
	t.Cleanup(resetCustodyForTesting)

	handle := openRawHandle(t, path)
	t.Cleanup(func() { RAWClose(stringObj(handle)) })

	openTestCase(t, "IR-1", "examiner")
	if _, errObj := unwrapPair(t, RAWReadAt(stringObj(handle), intObj(0), intObj(16))); errObj != nil {
		t.Fatalf("raw_read_at failed: %s", errObj.Message)
	}

	if entries := evidenceEntries(t, currentManifest(t)); len(entries) != 0 {
		t.Fatalf("manifest claims %d evidence entries for a handle opened before the case", len(entries))
	}
}

func TestCaseEvidenceRegistersAFileNoOpenerTouches(t *testing.T) {
	path, digest := writeTestImage(t, "carved.bin", 1024)
	openTestCase(t, "IR-1", "examiner")

	value, errObj := unwrapPair(t, CaseEvidence(
		stringObj(path),
		makeHashObject(map[string]object.Object{"hash": stringObj("sha256")}),
	))
	if errObj != nil {
		t.Fatalf("case_evidence failed: %s", errObj.Message)
	}
	// A digest was asked for on this one file even though the case as a whole
	// took none.
	if got := mustHashStringValue(t, value.(*object.Hash), "hash"); got != digest {
		t.Fatalf("hash = %q, want %q", got, digest)
	}

	entries := evidenceEntries(t, currentManifest(t))
	if len(entries) != 1 {
		t.Fatalf("manifest holds %d evidence entries, want 1", len(entries))
	}
	if !mustHashValue(t, entries[0], "hashed").(*object.Boolean).Value {
		t.Fatal("the entry is not marked as hashed")
	}
}

func TestCaseEvidenceRefusesWhatItCannotRead(t *testing.T) {
	openTestCase(t, "IR-1", "examiner")

	_, errObj := unwrapPairNoFatal(CaseEvidence(stringObj(filepath.Join(t.TempDir(), "absent.bin"))))
	if errObj == nil {
		t.Fatal("case_evidence accepted a file that is not there")
	}
	if !strings.Contains(errObj.Message, "cannot be read") {
		t.Fatalf("unhelpful message: %s", errObj.Message)
	}
}

func TestCaseVerifyReportsDrift(t *testing.T) {
	path, _ := writeTestImage(t, "disk.dd", 1024)
	openTestCase(t, "IR-1", "examiner",
		makeHashObject(map[string]object.Object{"hash": stringObj("sha256")}))

	handle := openRawHandle(t, path)
	RAWClose(stringObj(handle))

	report, errObj := unwrapPair(t, CaseVerify())
	if errObj != nil {
		t.Fatalf("case_verify failed: %s", errObj.Message)
	}
	if got := mustHashIntValue(t, report.(*object.Hash), "unchanged"); got != 1 {
		t.Fatalf("unchanged = %d on an untouched file", got)
	}

	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatalf("rewriting the image: %v", err)
	}

	report, errObj = unwrapPair(t, CaseVerify())
	if errObj != nil {
		t.Fatalf("case_verify failed: %s", errObj.Message)
	}
	hash := report.(*object.Hash)
	if got := mustHashIntValue(t, hash, "changed"); got != 1 {
		t.Fatalf("changed = %d after the file was rewritten", got)
	}

	source := manifestArray(t, hash, "sources")[0].(*object.Hash)
	if got := mustHashStringValue(t, source, "status"); got != "changed" {
		t.Fatalf("status = %q", got)
	}
	if got := mustHashStringValue(t, source, "basis"); got != "digest" {
		t.Fatalf("basis = %q; a case with a hash policy must compare digests", got)
	}
	if mustHashStringValue(t, source, "hash_now") == mustHashStringValue(t, source, "hash_at_open") {
		t.Fatal("the two digests are equal on a file that changed")
	}
}

// Without a digest the check is weaker, and the report has to say so rather than
// let the reader assume the stronger answer.
func TestCaseVerifyNamesTheWeakerBasis(t *testing.T) {
	path, _ := writeTestImage(t, "disk.dd", 1024)
	openTestCase(t, "IR-1", "examiner")

	handle := openRawHandle(t, path)
	RAWClose(stringObj(handle))

	// A size change is visible even without a digest.
	if err := os.WriteFile(path, []byte("shorter"), 0o600); err != nil {
		t.Fatalf("rewriting the image: %v", err)
	}

	report, errObj := unwrapPair(t, CaseVerify())
	if errObj != nil {
		t.Fatalf("case_verify failed: %s", errObj.Message)
	}
	source := manifestArray(t, report.(*object.Hash), "sources")[0].(*object.Hash)
	if got := mustHashStringValue(t, source, "basis"); got != "size and mod time" {
		t.Fatalf("basis = %q", got)
	}
	if got := mustHashStringValue(t, source, "status"); got != "changed" {
		t.Fatalf("status = %q", got)
	}
}

func TestCaseVerifyReportsAVanishedSource(t *testing.T) {
	path, _ := writeTestImage(t, "disk.dd", 512)
	openTestCase(t, "IR-1", "examiner")

	handle := openRawHandle(t, path)
	RAWClose(stringObj(handle))
	if err := os.Remove(path); err != nil {
		t.Fatalf("removing the image: %v", err)
	}

	report, errObj := unwrapPair(t, CaseVerify())
	if errObj != nil {
		t.Fatalf("case_verify failed: %s", errObj.Message)
	}
	if got := mustHashIntValue(t, report.(*object.Hash), "missing"); got != 1 {
		t.Fatalf("missing = %d after the source was deleted", got)
	}
}

// A verification is part of the record, not a side channel.
func TestCaseVerifyLandsInTheTimeline(t *testing.T) {
	openTestCase(t, "IR-1", "examiner")

	if _, errObj := unwrapPair(t, CaseVerify()); errObj != nil {
		t.Fatalf("case_verify failed: %s", errObj.Message)
	}

	timeline := manifestArray(t, currentManifest(t), "timeline")
	last := timeline[len(timeline)-1].(*object.Hash)
	if got := mustHashStringValue(t, last, "event"); got != "verify" {
		t.Fatalf("last timeline event = %q, want verify", got)
	}
}

// A digest over a disk image can take minutes, and holding the case lock for it
// would serialise every other evidence read in the program. This is the check
// that the lock is not held across the hash.
func TestEvidenceRegistrationDoesNotSerialiseOnHashing(t *testing.T) {
	first, _ := writeTestImage(t, "one.dd", 1<<20)
	second, _ := writeTestImage(t, "two.dd", 1<<20)
	openTestCase(t, "IR-1", "examiner",
		makeHashObject(map[string]object.Object{"hash": stringObj("sha256")}))

	done := make(chan struct{}, 2)
	for _, path := range []string{first, second} {
		go func(p string) {
			custodyRecordOpen("raw_open", "", p)
			done <- struct{}{}
		}(path)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("concurrent evidence registration deadlocked")
		}
	}

	if entries := evidenceEntries(t, currentManifest(t)); len(entries) != 2 {
		t.Fatalf("manifest holds %d evidence entries, want 2", len(entries))
	}
}
