package builtin

// M26-CUS-026: the three verifiers in this package that read the first JSON
// document in a file and then vouched for the file.
//
// Each test appends to a document the program itself sealed. Each one has a
// whitespace half beside the refusals, and that half is not a courtesy: every
// one of these documents is written as MarshalIndent with a '\n' appended, so
// the byte after the document is already whitespace in every file the program
// produces, and a check that refused trailing bytes outright would refuse all
// of them.
//
// The offset in each refusal is the end of the sealed document, which for a
// file written this way is len(file)-1: the terminating newline is not part of
// the value. It is hand-computed here and not read back from the code under
// test.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// The tails that must still be read. A rewrite interrupted between the
// truncate and the write leaves padding, and so does an editor.
var sealedAcceptedTails = []struct{ name, tail string }{
	{"nothing at all", ""},
	{"one newline", "\n"},
	{"one crlf", "\r\n"},
	{"spaces, tabs and both endings", "  \t\r\n \n"},
}

// The tails that must be refused. The three marked (More) are the ones
// json.Decoder.More() reports as "nothing follows", so a fix that asked More()
// alone would have passed them; see security/json_tail.go.
var sealedRefusedTails = []struct{ name, tail string }{
	{"a second document", "\n%s"},
	{"text that is not JSON", "\nnot json {{{"},
	{"a bare closing brace (More)", "}"},
	{"a bare closing bracket (More)", "]"},
	{"a closing brace and then a whole second document (More)", "\n}\n%s"},
}

// tailOf fills in the %s of a case's tail with the document itself, so the
// appended document is a real one rather than a fragment.
func tailOf(pattern string, document []byte) []byte {
	if !strings.Contains(pattern, "%s") {
		return []byte(pattern)
	}
	return []byte(fmt.Sprintf(pattern, document))
}

// withSealedTail copies rather than appending in place: append on a slice with
// spare capacity would write the tail into the document every later case reads.
func withSealedTail(document, tail []byte) []byte {
	out := make([]byte, 0, len(document)+len(tail))
	out = append(out, document...)
	return append(out, tail...)
}

// A case manifest with a second manifest appended reported hash_matches,
// signed and signature_valid all true and named the first document's examiner.
// This is also how a review request reads a manifest (case_review.go), through
// the same custodyManifestDocument, so both readers are fixed by one check.
func TestCaseManifestVerifyRefusesWhatTheSealDoesNotCover(t *testing.T) {
	useTestKeyStore(t)
	path, _ := writeTestImage(t, "disk.dd", 2048)
	openTestCase(t, "IR-SEAL-TAIL", "Examiner One",
		makeHashObject(map[string]object.Object{"hash": stringObj("sha256")}))
	handle := openRawHandle(t, path)
	RAWClose(stringObj(handle))

	manifestPath := writeManifest(t)
	original, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if original[len(original)-1] != '\n' {
		t.Fatal("case_write no longer terminates the manifest with a newline, " +
			"which is the whole reason trailing whitespace has to be read")
	}
	ends := fmt.Sprintf("byte %d", len(original)-1)

	// The appended manifest names a different examiner, which is the point of
	// the row: "verified" was attached to a file that said two things.
	other := bytes.Replace(original, []byte(`"Examiner One"`), []byte(`"Examiner Two"`), -1)
	if bytes.Equal(other, original) {
		t.Fatal("the fixture no longer names the examiner, so the appended document is not a different one")
	}

	verify := func(t *testing.T, whole []byte) (*object.Hash, *object.Error) {
		t.Helper()
		if err := os.WriteFile(manifestPath, whole, 0o600); err != nil {
			t.Fatal(err)
		}
		value, errObj := unwrapPairNoFatal(CaseManifestVerify(stringObj(manifestPath)))
		if errObj != nil {
			return nil, errObj
		}
		hash, ok := value.(*object.Hash)
		if !ok {
			t.Fatalf("case_manifest_verify returned %T, want HASH", value)
		}
		return hash, nil
	}

	for _, c := range sealedRefusedTails {
		t.Run(c.name, func(t *testing.T) {
			hash, errObj := verify(t, withSealedTail(original, tailOf(c.tail, other)))
			if errObj == nil {
				t.Fatalf("a manifest with %s was verified: hash_matches=%v signed=%v signature_valid=%v",
					c.name, mustBool(t, hash, "hash_matches"), mustBool(t, hash, "signed"),
					mustBool(t, hash, "signature_valid"))
			}
			if !strings.Contains(errObj.Message, ends) {
				t.Fatalf("the refusal does not say where the sealed manifest ends (%s): %s", ends, errObj.Message)
			}
			if !strings.Contains(errObj.Message, "is not verified") {
				t.Fatalf("the refusal does not read as a verification failure: %s", errObj.Message)
			}
		})
	}

	for _, c := range sealedAcceptedTails {
		t.Run("and then "+c.name, func(t *testing.T) {
			hash, errObj := verify(t, withSealedTail(original, []byte(c.tail)))
			if errObj != nil {
				t.Fatalf("a manifest and then %s was refused: %s", c.name, errObj.Message)
			}
			if !mustBool(t, hash, "hash_matches") || !mustBool(t, hash, "signed") ||
				!mustBool(t, hash, "signature_valid") {
				t.Fatalf("hash_matches=%v signed=%v signature_valid=%v on a manifest padded with whitespace",
					mustBool(t, hash, "hash_matches"), mustBool(t, hash, "signed"),
					mustBool(t, hash, "signature_valid"))
			}
		})
	}
}

// A disclosure package whose disclosure.json held a second copy of itself was
// reported verified with all eleven checks passing.
func TestDiscloseVerifyRefusesWhatTheSealDoesNotCover(t *testing.T) {
	f := newDiscloseFixture(t)
	issued := f.issue(t, "counsel", "Counsel for the respondent")
	dir, root := f.bundle(t, keyFieldString(t, issued, "disclosure_uid"))
	path := filepath.Join(dir, discloseManifestName)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if original[len(original)-1] != '\n' {
		t.Fatal("disclose_bundle no longer terminates the manifest with a newline")
	}
	ends := fmt.Sprintf("byte %d", len(original)-1)

	verify := func(t *testing.T, whole []byte) (*object.Hash, *object.Error) {
		t.Helper()
		if err := os.WriteFile(path, whole, 0o600); err != nil {
			t.Fatal(err)
		}
		purposeStub(t, map[string]string{BuiltinNameDiscloseVerify: testGrantPassphrase})
		value, errObj := unwrapPairNoFatal(DiscloseVerify(stringObj(dir), stringObj(root)))
		if errObj != nil {
			return nil, errObj
		}
		hash, ok := value.(*object.Hash)
		if !ok {
			t.Fatalf("disclose_verify returned %T, want HASH", value)
		}
		return hash, nil
	}

	for _, c := range sealedRefusedTails {
		t.Run(c.name, func(t *testing.T) {
			// A copy of the manifest, so nothing about the appended document's
			// content explains the refusal: what is refused is a file that is
			// two documents where the seal commits to one.
			hash, errObj := verify(t, withSealedTail(original, tailOf(c.tail, original)))
			if errObj == nil {
				t.Fatalf("a package whose manifest carried %s was read: verified=%v checks=%v",
					c.name, discloseBool(t, hash, "verified"), discloseChecks(t, hash))
			}
			if !strings.Contains(errObj.Message, ends) {
				t.Fatalf("the refusal does not say where the sealed manifest ends (%s): %s", ends, errObj.Message)
			}
			if !strings.Contains(errObj.Message, "is not verified") {
				t.Fatalf("the refusal does not read as a verification failure: %s", errObj.Message)
			}
		})
	}

	for _, c := range sealedAcceptedTails {
		t.Run("and then "+c.name, func(t *testing.T) {
			hash, errObj := verify(t, withSealedTail(original, []byte(c.tail)))
			if errObj != nil {
				t.Fatalf("a manifest and then %s was refused: %s", c.name, errObj.Message)
			}
			// The narrow assertion on purpose: the seal is computed over the
			// decoded document, so whitespace cannot move it. Whether every
			// other check still passes depends on what else in the package
			// names this file's digest, which is not what this test is about.
			checks := discloseChecks(t, hash)
			if checks["manifest_seal"] != "pass" {
				t.Fatalf("manifest_seal is %q on a manifest padded with whitespace; all checks: %v",
					checks["manifest_seal"], checks)
			}
			t.Logf("and then %s: verified=%v", c.name, discloseBool(t, hash, "verified"))
		})
	}
}

// The fourth site. The row's note listed it as "not checked (the audit verifier
// decodes in a loop)". It does not decode in a loop: it decodes one document
// and then loops over the array inside it, so the head commits to the entries
// of the first document and nothing looks at the rest of the file. The chain's
// one property is stated in audit.go as "editing an entry changes its hash";
// appending a document edits no entry, which is exactly why the head cannot see
// it.
func TestAuditVerifyRefusesWhatTheChainDoesNotCover(t *testing.T) {
	useTestAuditChain(t)
	for _, stage := range []string{"vm-run", "vm-decode", "runner:startup"} {
		auditLog.AuditEvent("integrity_failed", stage)
	}
	path := filepath.Join(t.TempDir(), "audit.json")
	writeAuditLog(t, path)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if original[len(original)-1] != '\n' {
		t.Fatal("audit_write no longer terminates the log with a newline")
	}
	ends := fmt.Sprintf("byte %d", len(original)-1)

	verify := func(t *testing.T, whole []byte) (*object.Hash, *object.Error) {
		t.Helper()
		if err := os.WriteFile(path, whole, 0o600); err != nil {
			t.Fatal(err)
		}
		value, errObj := unwrapPairNoFatal(AuditVerify(stringObj(path)))
		if errObj != nil {
			return nil, errObj
		}
		hash, ok := value.(*object.Hash)
		if !ok {
			t.Fatalf("audit_verify returned %T, want HASH", value)
		}
		return hash, nil
	}

	for _, c := range sealedRefusedTails {
		t.Run(c.name, func(t *testing.T) {
			hash, errObj := verify(t, withSealedTail(original, tailOf(c.tail, original)))
			if errObj == nil {
				t.Fatalf("a log with %s was checked: links_intact=%v head_matches=%v", c.name,
					mustHashBoolValue(t, hash, "links_intact"), mustHashBoolValue(t, hash, "head_matches"))
			}
			if !strings.Contains(errObj.Message, ends) {
				t.Fatalf("the refusal does not say where the log ends (%s): %s", ends, errObj.Message)
			}
			if !strings.Contains(errObj.Message, "is not verified") {
				t.Fatalf("the refusal does not read as a verification failure: %s", errObj.Message)
			}
		})
	}

	for _, c := range sealedAcceptedTails {
		t.Run("and then "+c.name, func(t *testing.T) {
			hash, errObj := verify(t, withSealedTail(original, []byte(c.tail)))
			if errObj != nil {
				t.Fatalf("a log and then %s was refused: %s", c.name, errObj.Message)
			}
			if !mustHashBoolValue(t, hash, "links_intact") || !mustHashBoolValue(t, hash, "head_matches") {
				t.Fatalf("links_intact=%v head_matches=%v on a log padded with whitespace",
					mustHashBoolValue(t, hash, "links_intact"), mustHashBoolValue(t, hash, "head_matches"))
			}
		})
	}
}
