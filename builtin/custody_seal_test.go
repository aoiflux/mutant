package builtin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
	"mutant/security"
)

// useTestKeyStore points the local signing key pair at a temp directory, so a
// test signs with a throwaway key rather than the examiner's.
func useTestKeyStore(t *testing.T) {
	t.Helper()
	security.SetLocalKeyStoreDirForTesting(t.TempDir())
	t.Cleanup(func() { security.SetLocalKeyStoreDirForTesting("") })
}

func writeManifest(t *testing.T, options ...object.Object) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "manifest.json")
	args := append([]object.Object{stringObj(path)}, options...)
	value, errObj := unwrapPair(t, CaseWrite(args...))
	if errObj != nil {
		t.Fatalf("case_write failed: %s", errObj.Message)
	}
	if got := mustHashStringValue(t, value.(*object.Hash), "status"); got != "ok" {
		t.Fatalf("status = %q", got)
	}
	return path
}

func verifyManifest(t *testing.T, path string) *object.Hash {
	t.Helper()

	value, errObj := unwrapPair(t, CaseManifestVerify(stringObj(path)))
	if errObj != nil {
		t.Fatalf("case_manifest_verify failed: %s", errObj.Message)
	}
	return value.(*object.Hash)
}

func mustBool(t *testing.T, hash *object.Hash, key string) bool {
	t.Helper()
	value, ok := mustHashValue(t, hash, key).(*object.Boolean)
	if !ok {
		t.Fatalf("key %s is not BOOLEAN", key)
	}
	return value.Value
}

func TestAWrittenManifestVerifiesAgainstItself(t *testing.T) {
	useTestKeyStore(t)
	path, _ := writeTestImage(t, "disk.dd", 2048)
	openTestCase(t, "IR-2026-0413", "G. Gogia",
		makeHashObject(map[string]object.Object{"hash": stringObj("sha256")}))

	handle := openRawHandle(t, path)
	RAWClose(stringObj(handle))
	if _, errObj := unwrapPair(t, CaseNote(stringObj("imaged at the scene"))); errObj != nil {
		t.Fatalf("case_note failed: %s", errObj.Message)
	}

	manifestPath := writeManifest(t)
	result := verifyManifest(t, manifestPath)

	if !mustBool(t, result, "hash_matches") {
		t.Fatalf("the manifest does not hash to its own seal:\n  recorded %s\n  computed %s",
			mustHashStringValue(t, result, "manifest_hash"),
			mustHashStringValue(t, result, "computed_hash"))
	}
	if !mustBool(t, result, "signed") {
		t.Fatal("the manifest was written unsigned")
	}
	if !mustBool(t, result, "signature_valid") {
		t.Fatalf("the signature does not hold: %s", mustHashStringValue(t, result, "signature_detail"))
	}
	if got := mustHashStringValue(t, result, "case_id"); got != "IR-2026-0413" {
		t.Fatalf("case_id = %q", got)
	}
	if got := mustHashStringValue(t, result, "examiner"); got != "G. Gogia" {
		t.Fatalf("examiner = %q", got)
	}
}

// The whole point of the seal. A document a court is handed must not be
// alterable without that being detectable by the reader alone.
func TestTamperingWithAWrittenManifestIsDetected(t *testing.T) {
	useTestKeyStore(t)
	openTestCase(t, "IR-1", "G. Gogia")
	manifestPath := writeManifest(t)

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("reading the manifest: %v", err)
	}
	altered := strings.Replace(string(raw), `"G. Gogia"`, `"somebody else"`, 1)
	if altered == string(raw) {
		t.Fatal("the examiner's name is not in the document; this test is checking nothing")
	}
	if err := os.WriteFile(manifestPath, []byte(altered), 0o600); err != nil {
		t.Fatalf("rewriting the manifest: %v", err)
	}

	result := verifyManifest(t, manifestPath)
	if mustBool(t, result, "hash_matches") {
		t.Fatal("an altered manifest still hashes to its seal")
	}
	if mustBool(t, result, "signature_valid") {
		t.Fatal("the signature still holds over an altered manifest")
	}
}

// Reformatting is not tampering: the canonical form is re-derived from the
// parsed document, so indentation and key order in the file do not matter.
func TestReformattingAManifestDoesNotBreakItsSeal(t *testing.T) {
	useTestKeyStore(t)
	openTestCase(t, "IR-1", "G. Gogia")
	manifestPath := writeManifest(t)

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("reading the manifest: %v", err)
	}
	var document map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("decoding the manifest: %v", err)
	}
	compact, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("re-encoding the manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, compact, 0o600); err != nil {
		t.Fatalf("rewriting the manifest: %v", err)
	}

	result := verifyManifest(t, manifestPath)
	if !mustBool(t, result, "hash_matches") {
		t.Fatal("reformatting broke the hash; the canonical form is not canonical")
	}
	if !mustBool(t, result, "signature_valid") {
		t.Fatalf("reformatting broke the signature: %s", mustHashStringValue(t, result, "signature_detail"))
	}
}

// A machine with no key store still produces a checkable document -- it just
// says so rather than looking signed.
func TestAnUnsignedManifestSaysSo(t *testing.T) {
	useTestKeyStore(t)
	openTestCase(t, "IR-1", "G. Gogia")

	manifestPath := writeManifest(t, makeHashObject(map[string]object.Object{"sign": boolObj(false)}))
	result := verifyManifest(t, manifestPath)

	if mustBool(t, result, "signed") {
		t.Fatal("a manifest written with sign:false reports itself as signed")
	}
	if !mustBool(t, result, "hash_matches") {
		t.Fatal("an unsigned manifest does not hash to its own seal")
	}
	if mustBool(t, result, "signature_valid") {
		t.Fatal("an unsigned manifest reports a valid signature")
	}
}

func TestCaseManifestVerifyRefusesWhatIsNotAManifest(t *testing.T) {
	dir := t.TempDir()

	notJSON := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(notJSON, []byte("this is not a manifest"), 0o600); err != nil {
		t.Fatalf("writing the decoy: %v", err)
	}
	unsealed := filepath.Join(dir, "plain.json")
	if err := os.WriteFile(unsealed, []byte(`{"case": {"id": "IR-1"}}`), 0o600); err != nil {
		t.Fatalf("writing the decoy: %v", err)
	}

	for _, tc := range []struct{ name, path, want string }{
		{"a file that is not JSON", notJSON, "is not a manifest"},
		{"a JSON document with no seal", unsealed, "has no seal"},
		{"a file that is not there", filepath.Join(dir, "absent.json"), "case_manifest_verify"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, errObj := unwrapPairNoFatal(CaseManifestVerify(stringObj(tc.path)))
			if errObj == nil {
				t.Fatal("want an error, got none")
			}
			if !strings.Contains(errObj.Message, tc.want) {
				t.Fatalf("message %q does not contain %q", errObj.Message, tc.want)
			}
		})
	}
}

// "This exact bytecode wrote this" is the claim, so the manifest has to carry
// the artifact's digest -- and has to decline to invent one when the program was
// not started through the runner.
func TestTheManifestNamesTheArtifactThatProducedIt(t *testing.T) {
	resetProgramIdentityForTesting()
	t.Cleanup(resetProgramIdentityForTesting)

	openTestCase(t, "IR-1", "examiner")
	program := manifestSection(t, currentManifest(t), "program")
	if mustBool(t, program, "recorded") {
		t.Fatal("the manifest claims an artifact identity it was never given")
	}
	if mustHashStringValue(t, program, "detail") == "" {
		t.Fatal("an unrecorded program says nothing about why")
	}

	artifact := []byte("pretend this is signed bytecode")
	SetProgramIdentity("O:/cases/IR-1/collect.mu", artifact)

	program = manifestSection(t, currentManifest(t), "program")
	if !mustBool(t, program, "recorded") {
		t.Fatal("the manifest did not pick up the artifact identity")
	}
	if got := mustHashStringValue(t, program, "path"); got != "O:/cases/IR-1/collect.mu" {
		t.Fatalf("path = %q", got)
	}
	// The digest of those exact bytes, computed here rather than taken from the
	// code under test.
	sum := sha256.Sum256(artifact)
	if got, want := mustHashStringValue(t, program, "hash"), hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("hash = %q, want %q", got, want)
	}
	if got := mustHashStringValue(t, program, "hash_algo"); got != "sha256" {
		t.Fatalf("hash_algo = %q", got)
	}
}

func TestCaseWriteRefusesWithoutACase(t *testing.T) {
	resetCustodyForTesting()
	t.Cleanup(resetCustodyForTesting)

	_, errObj := unwrapPairNoFatal(CaseWrite(stringObj(filepath.Join(t.TempDir(), "m.json"))))
	if errObj == nil {
		t.Fatal("case_write succeeded with no case ever opened")
	}
	if !strings.Contains(errObj.Message, "no case has been opened") {
		t.Fatalf("unhelpful message: %s", errObj.Message)
	}
}
