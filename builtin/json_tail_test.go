package builtin

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// The tails every file this build verifies has to refuse. The four marked
// (More) are the ones json.Decoder.More() reports as nothing-more-to-read,
// because it is defined as `err == nil && c != ']' && c != '}'`; after a stray
// closing delimiter no byte of the rest of the file is examined at all.
var tailsThatMustBeRefused = []struct{ name, tail string }{
	{"a second document", `{"format":"x"}`},
	{"a second document on its own line", "\n{\"format\":\"x\"}\n"},
	{"a bare closing brace (More)", "}"},
	{"a bare closing bracket (More)", "]"},
	{"a closing brace and then a payload (More)", "} and then anything at all"},
	{"a closing brace, a newline and a whole second document (More)", "\n}\n{\"format\":\"x\"}"},
	{"a word", "bogus"},
	{"a comma and a second document", `,{"format":"x"}`},
	{"a NUL byte", "\x00"},
	{"a utf-8 byte order mark", "\xef\xbb\xbf"},
}

// A rewrite interrupted between the truncate and the write leaves padding, so
// these have to keep opening. Refusing them would turn a survivable crash into
// a lost case file.
var tailsThatMustStillOpen = []string{"", "\n", "\r\n", "  \t\r\n \n"}

func withTail(document []byte, tail string) []byte {
	out := make([]byte, 0, len(document)+len(tail))
	out = append(out, document...)
	return append(out, tail...)
}

// A sealed manifest that verifies against itself still verifies with trailing
// whitespace, and does not verify with anything else behind it. This is the
// release blocker: the seal covers the document the decoder read, so a second
// document sitting after the first changed no hash, and the file was reported
// verified with content in it that nothing had checked.
//
// custodyManifestDocument is the one implementation behind case_manifest_verify
// and a review request's manifest read, which is why one test covers both.
func TestASealedManifestHoldsOneDocument(t *testing.T) {
	useTestKeyStore(t)
	openTestCase(t, "IR-2026-0413", "G. Gogia",
		makeHashObject(map[string]object.Object{"hash": stringObj("sha256")}))
	if _, errObj := unwrapPair(t, CaseNote(stringObj("imaged at the scene"))); errObj != nil {
		t.Fatalf("case_note failed: %s", errObj.Message)
	}
	path := writeManifest(t)
	verifyManifest(t, path)

	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tail := range tailsThatMustStillOpen {
		if err := os.WriteFile(path, withTail(original, tail), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, errObj := unwrapPairNoFatal(CaseManifestVerify(stringObj(path))); errObj != nil {
			t.Errorf("a manifest padded with %q no longer verifies: %s", tail, errObj.Message)
		}
	}
	for _, c := range tailsThatMustBeRefused {
		if err := os.WriteFile(path, withTail(original, c.tail), 0o600); err != nil {
			t.Fatal(err)
		}
		_, errObj := unwrapPairNoFatal(CaseManifestVerify(stringObj(path)))
		if errObj == nil {
			t.Errorf("a manifest and then %s: reported on without a word about the tail", c.name)
			continue
		}
		if !strings.Contains(errObj.Message, "ends at byte") {
			t.Errorf("a manifest and then %s: refused without naming the offset: %s", c.name, errObj.Message)
		}
	}
}

func TestAnAuditLogHoldsOneDocument(t *testing.T) {
	useTestAuditChain(t)
	useTestKeyStore(t)
	openTestCase(t, "IR-2026-0414", "G. Gogia",
		makeHashObject(map[string]object.Object{"hash": stringObj("sha256")}))
	if _, errObj := unwrapPair(t, CaseNote(stringObj("an event to put in the chain"))); errObj != nil {
		t.Fatalf("case_note failed: %s", errObj.Message)
	}
	path := filepath.Join(t.TempDir(), "audit.json")
	writeAuditLog(t, path)
	verifyAuditLog(t, stringObj(path))

	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range tailsThatMustBeRefused {
		if err := os.WriteFile(path, withTail(original, c.tail), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, errObj := unwrapPairNoFatal(AuditVerify(stringObj(path))); errObj == nil {
			t.Errorf("an audit log and then %s: verified", c.name)
		}
	}
	for _, tail := range tailsThatMustStillOpen {
		if err := os.WriteFile(path, withTail(original, tail), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, errObj := unwrapPairNoFatal(AuditVerify(stringObj(path))); errObj != nil {
			t.Errorf("an audit log padded with %q no longer verifies: %s", tail, errObj.Message)
		}
	}
}

// disclosure.json is read by disclose_verify before anything is derived from
// it. The control is the point of this test: with no tail the same document
// gets past the decode and is refused for what it does not say, which is how
// the test shows that the tail is what stopped the others.
func TestADisclosureManifestHoldsOneDocument(t *testing.T) {
	document := []byte(`{"format":"` + discloseManifestFormat + `"}`)
	write := func(t *testing.T, body []byte) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, discloseManifestName), body, 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	_, errObj := unwrapPairNoFatal(DiscloseVerify(stringObj(write(t, document)), &object.Null{}))
	if errObj == nil {
		t.Fatal("a manifest holding only a format was accepted, so this test's control is wrong")
	}
	if strings.Contains(errObj.Message, "ends at byte") {
		t.Fatalf("the control document was refused for a tail it does not have: %s", errObj.Message)
	}
	for _, c := range tailsThatMustBeRefused {
		_, errObj := unwrapPairNoFatal(DiscloseVerify(stringObj(write(t, withTail(document, c.tail))), &object.Null{}))
		if errObj == nil {
			t.Errorf("a disclosure manifest and then %s: accepted", c.name)
			continue
		}
		if !strings.Contains(errObj.Message, "ends at byte") {
			t.Errorf("a disclosure manifest and then %s: refused for something else: %s", c.name, errObj.Message)
		}
	}
}

func TestARegistryHiveHoldsOneDocument(t *testing.T) {
	document := []byte(`{"keys":[]}`)
	write := func(t *testing.T, body []byte) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "hive.json")
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if _, errObj := unwrapPairNoFatal(RegOpen(stringObj(write(t, document)))); errObj != nil {
		t.Fatalf("an empty hive does not open, so this test's control is wrong: %s", errObj.Message)
	}
	for _, c := range tailsThatMustBeRefused {
		if _, errObj := unwrapPairNoFatal(RegOpen(stringObj(write(t, withTail(document, c.tail))))); errObj == nil {
			t.Errorf("a hive and then %s: opened", c.name)
		}
	}
	for _, tail := range tailsThatMustStillOpen {
		if _, errObj := unwrapPairNoFatal(RegOpen(stringObj(write(t, withTail(document, tail))))); errObj != nil {
			t.Errorf("a hive padded with %q no longer opens: %s", tail, errObj.Message)
		}
	}
}

// A JWT's header carries alg, the field that decides whether a signature is
// checked at all. Two parsers that disagree about a token's alg is the oldest
// JWT bug there is, and a header segment holding two documents is how they come
// to disagree: this build read the first and the next library along may read
// the last. The claims go through the same decoder, so sub and exp disagree the
// same way.
func TestAJWTSegmentHoldsOneDocument(t *testing.T) {
	segment := func(body string) string { return base64.RawURLEncoding.EncodeToString([]byte(body)) }
	token := func(header, claims string) object.Object {
		return stringObj(segment(header) + "." + segment(claims))
	}
	if _, errObj := unwrapPairNoFatal(JWTDecode(token(`{"alg":"none"}`, `{"sub":"alice"}`))); errObj != nil {
		t.Fatalf("an ordinary token does not decode, so this test's control is wrong: %s", errObj.Message)
	}
	hostile := []struct{ name, header, claims string }{
		{"two algs in the header", `{"alg":"none"}{"alg":"RS256"}`, `{"sub":"alice"}`},
		{"an alg hidden behind a closing brace", `{"alg":"none"}}{"alg":"RS256"}`, `{"sub":"alice"}`},
		{"two subjects in the claims", `{"alg":"none"}`, `{"sub":"alice"}{"sub":"root"}`},
		{"a subject hidden behind a closing brace", `{"alg":"none"}`, `{"sub":"alice"}} {"sub":"root"}`},
	}
	for _, h := range hostile {
		if _, errObj := unwrapPairNoFatal(JWTDecode(token(h.header, h.claims))); errObj == nil {
			t.Errorf("%s: decoded, and this build's answer is now one of two a reader could get", h.name)
		}
	}
	for _, tail := range tailsThatMustStillOpen {
		if _, errObj := unwrapPairNoFatal(JWTDecode(token(`{"alg":"none"}`+tail, `{"sub":"alice"}`+tail))); errObj != nil {
			t.Errorf("a token whose segments carry %q no longer decodes: %s", tail, errObj.Message)
		}
	}
}
