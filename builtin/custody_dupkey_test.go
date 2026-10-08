package builtin

// M26-CUS-032: a repeated field name in a sealed document is authenticated
// away. The decoder keeps the LAST copy, and the hash and the signature are
// computed over a canonical form REBUILT from what it kept, so the first copy
// is a value a reader sees and nothing checked.
//
// M26-BLT-027: the same bytes through jwt_decode, which is not a seal but gives
// the same wrong answer -- `alg` is the field that decides whether a signature
// is checked at all. Not M26-BLT-025, which is the tail row for the same
// function -- two documents in one segment rather than two names in one
// document -- and which b47e28c closed.
//
// The forgery inserts the attacker's copy IN FRONT of the real one, which is
// where it has to go. Inserted after, the decoder would keep the attacker's
// value and the canonical form would change, so the hash would fail and there
// would be no row.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"mutant/object"
	"mutant/security"
)

// forgeRepeatedField puts a second copy of one field in front of the real one
// and leaves the rest of the document alone, byte for byte.
func forgeRepeatedField(t *testing.T, document []byte, field, value string) []byte {
	t.Helper()
	needle := []byte(fmt.Sprintf("%q:", field))
	// Exactly once, so which object the copy lands in is not a guess. A name
	// that appears twice already would make the insertion land in whichever
	// object came first in the marshalled output, and the subtest would be
	// describing a different document than the one it names.
	if count := bytes.Count(document, needle); count != 1 {
		t.Fatalf("the fixture names %q %d times and this helper needs exactly one, so the "+
			"insertion point is not determined", field, count)
	}
	index := bytes.Index(document, needle)
	insert := []byte(fmt.Sprintf("%q: %q,\n  ", field, value))
	out := make([]byte, 0, len(document)+len(insert))
	out = append(out, document[:index]...)
	out = append(out, insert...)
	return append(out, document[index:]...)
}

// The row's own case, end to end: a manifest the program sealed and signed
// itself, edited with nothing but a text editor's worth of bytes.
//
// Measured before the fix: hash_matches, signed and signature_valid were all
// true on the forged file and the examiner read back as the honest one.
func TestCaseManifestVerifyRefusesARepeatedFieldTheSealDoesNotCover(t *testing.T) {
	useTestKeyStore(t)
	path, _ := writeTestImage(t, "disk.dd", 2048)
	openTestCase(t, "IR-DUP-KEY", "Examiner One",
		makeHashObject(map[string]object.Object{"hash": stringObj("sha256")}))
	handle := openRawHandle(t, path)
	RAWClose(stringObj(handle))

	manifestPath := writeManifest(t)
	original, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
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

	// The honest file still verifies. This half passes on the unfixed code too,
	// and it is here because the condition the fix was accepted under is that
	// the canonical form does not change: every manifest already sealed has to
	// go on verifying.
	t.Run("the honest manifest still verifies", func(t *testing.T) {
		hash, errObj := verify(t, original)
		if errObj != nil {
			t.Fatalf("the manifest this test just sealed was refused: %s", errObj.Message)
		}
		if !mustBool(t, hash, "hash_matches") || !mustBool(t, hash, "signed") ||
			!mustBool(t, hash, "signature_valid") {
			t.Fatalf("hash_matches=%v signed=%v signature_valid=%v on an untouched manifest",
				mustBool(t, hash, "hash_matches"), mustBool(t, hash, "signed"),
				mustBool(t, hash, "signature_valid"))
		}
	})

	// One nested field and one top-level section, because the canonical form is
	// a marshal of the whole decoded document and the dropped copy is uncovered
	// at either depth. Measured against the fixture rather than assumed: the
	// manifest case_write produces has eleven top-level keys -- audit, case,
	// classification, evidence, integrity, ledger_state, program, seal,
	// security_telemetry, timeline, tool -- and `examiner` lives inside `case`.
	// There is no top-level `case_id`; the case id is `case.id`.
	for _, field := range []string{"examiner", "integrity"} {
		t.Run("a second "+field+" in front of the real one", func(t *testing.T) {
			forged := forgeRepeatedField(t, original, field, "Mallory")

			// The forgery has to be a document that still parses AND still
			// decodes to exactly the honest document, or it proves nothing: it
			// is only because the two decode the same that the canonical form,
			// the hash and the signature are all identical. Comparing the whole
			// decoded document rather than looking up one key is what makes this
			// hold for a nested field, where a lookup by that name finds nil.
			var honest, decoded map[string]any
			if err := json.Unmarshal(original, &honest); err != nil {
				t.Fatalf("the honest manifest is not valid JSON: %s", err)
			}
			if err := json.Unmarshal(forged, &decoded); err != nil {
				t.Fatalf("the forged manifest is not valid JSON, so it is not this row's case: %s", err)
			}
			if !reflect.DeepEqual(honest, decoded) {
				t.Fatalf("the forged manifest decodes differently from the honest one, so the "+
					"canonical form changed and the hash would have caught it: the insertion "+
					"went in the wrong place and this subtest is not testing %s's case", field)
			}

			hash, errObj := verify(t, forged)
			if errObj == nil {
				t.Fatalf("a manifest naming %s twice was verified: hash_matches=%v signed=%v "+
					"signature_valid=%v -- the signature holds over bytes the verifier never read",
					field, mustBool(t, hash, "hash_matches"), mustBool(t, hash, "signed"),
					mustBool(t, hash, "signature_valid"))
			}
			if !strings.Contains(errObj.Message, field) {
				t.Errorf("the refusal does not name the repeated field %q: %s", field, errObj.Message)
			}
			if !strings.Contains(errObj.Message, "is not verified") {
				t.Errorf("the refusal does not read as a verification failure: %s", errObj.Message)
			}
		})
	}
}

// The canonical form is what the hash and the signature are computed over, so a
// change to it invalidates every manifest, key file and grant already written.
// The expected bytes are spelled out here rather than recomputed, so that a
// future edit to custodyCanonical fails this test instead of silently breaking
// sealed documents in the field.
func TestTheCanonicalFormIsUnchanged(t *testing.T) {
	manifest := map[string]any{
		"case_id":  "C-1",
		"examiner": "One",
		"opened":   json.Number("1"),
		"seal": map[string]any{
			"manifest_hash": "deadbeef",
			"signature":     "cafe",
		},
	}

	canonical, err := custodyCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}

	const want = `{"case_id":"C-1","examiner":"One","opened":1}`
	if string(canonical) != want {
		t.Fatalf("the canonical form changed, and every sealed document in the field is "+
			"verified against it:\n  want %s\n  got  %s", want, canonical)
	}
}

// Two implementations of one rule, which the purity boundary forces: json_parse
// is on the macro-safety allowlist in macro_safety.go, and the purity walk is
// default-deny on packages with mutant/security named as exactly the hop it
// exists to refuse -- so json_parse cannot call the security helper, and the
// security readers cannot call json_parse's.
//
// Two implementations that can disagree is the fault this whole kit is about, so
// the agreement is checked rather than assumed. Both are asked only the question
// they share: does this well-formed document repeat a name?
func TestTheTwoRepeatedKeyReadersAgree(t *testing.T) {
	corpus := []string{
		`{}`,
		`{"a":1}`,
		`{"a":1,"b":2}`,
		`{"a":1,"a":2}`,
		`{"a":1,"b":2,"a":3}`,
		`{"a":{"b":1,"b":2}}`,
		`{"a":{"b":1},"a":{"b":2}}`,
		`{"a":[{"b":1},{"b":2}]}`,
		`{"a":[{"b":1,"b":2}]}`,
		`{"a":"a"}`,
		`{"a":"b","b":"a"}`,
		`{"fields":["a","a"],"a":1}`,
		`{"a":[[{"b":1,"b":2}]]}`,
		`[{"a":1},{"a":1}]`,
		`[{"a":1,"a":2}]`,
		`[]`,
		`[1,2,3]`,
		`5`,
		`"text"`,
		`null`,
		`{"a":null,"a":null}`,
		`{"seal":{"manifest_hash":"aa","manifest_hash":"bb"}}`,
	}

	for _, document := range corpus {
		_, parseErr := decodeJSONDocument(document)
		parseRefused := parseErr != nil && strings.Contains(parseErr.Error(), "appears twice in one object")

		securityRefused := security.RefuseRepeatedKeys([]byte(document), "the document") != nil

		if parseRefused != securityRefused {
			t.Errorf("the two readers disagree about %s:\n  json_parse refuses: %v\n  "+
				"security refuses: %v\n  (json_parse said: %v)",
				document, parseRefused, securityRefused, parseErr)
		}
	}
}

// M26-BLT-027. A JWT whose claims name `sub` twice decoded to the last copy and
// reported no error, so this build answered one subject where the next library
// along answers the other, over the identical token. The JWS signature covers
// the base64 text and holds over both readings, so it is no help.
func TestJWTDecodeRefusesARepeatedClaim(t *testing.T) {
	segment := func(text string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(text))
	}

	for name, parts := range map[string][2]string{
		"a repeated claim": {`{"alg":"HS256","typ":"JWT"}`, `{"sub":"admin","sub":"guest"}`},
		"a repeated alg":   {`{"alg":"none","alg":"HS256"}`, `{"sub":"one"}`},
	} {
		t.Run(name, func(t *testing.T) {
			token := segment(parts[0]) + "." + segment(parts[1]) + ".c2ln"

			_, errObj := unwrapPairNoFatal(JWTDecode(stringObj(token)))
			if errObj == nil {
				t.Fatalf("a token with %s was decoded; whichever copy this build kept, "+
					"another reader of the same token keeps the other", name)
			}
			if !strings.Contains(errObj.Message, "twice in one object") {
				t.Errorf("the refusal does not say a name is repeated: %s", errObj.Message)
			}
		})
	}

	// The honest token still decodes. Nothing the encoder can write repeats a
	// name, so this check refuses no token that was issued properly.
	t.Run("an honest token still decodes", func(t *testing.T) {
		token := segment(`{"alg":"HS256","typ":"JWT"}`) + "." +
			segment(`{"sub":"1234567890","name":"John Doe"}`) + ".c2ln"
		if _, errObj := unwrapPairNoFatal(JWTDecode(stringObj(token))); errObj != nil {
			t.Fatalf("an ordinary token was refused: %s", errObj.Message)
		}
	})
}
