package security

import (
	"strings"
	"testing"
)

// The row's own case: a repeated name at the top level of a sealed document.
// Before this check, the decoder kept "One", the canonical form rebuilt from it
// was the honest document's byte for byte, and the honest signature verified
// over the forged file (M26-CUS-032).
func TestARepeatedNameIsRefused(t *testing.T) {
	forged := []byte(`{"case_id":"C-1","examiner":"Mallory","examiner":"One","opened":1}`)

	err := RefuseRepeatedKeys(forged, "the case manifest")
	if err == nil {
		t.Fatal("a document naming examiner twice was accepted; the first copy is a value " +
			"a reader sees and the canonical form rebuilt from the decode does not")
	}
	for _, want := range []string{"the case manifest", `"examiner"`, "twice in one object"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %s:\n  %s", want, err.Error())
		}
	}
}

// A repeated name inside the seal block is the same defect as one beside it, and
// the harder of the two to see: manifest_hash is the field the verifier compares
// against.
func TestARepeatedNameAtAnyDepthIsRefused(t *testing.T) {
	for name, document := range map[string]string{
		"inside the seal":           `{"case_id":"C-1","seal":{"manifest_hash":"aa","manifest_hash":"bb"}}`,
		"inside an array":           `{"files":[{"name":"a","sha256":"aa","sha256":"bb"}]}`,
		"three deep":                `{"a":{"b":{"c":1,"c":2}}}`,
		"inside an array of arrays": `{"a":[[{"b":1,"b":2}]]}`,
	} {
		if err := RefuseRepeatedKeys([]byte(document), "the document"); err == nil {
			t.Errorf("a name repeated %s was accepted: %s", name, document)
		}
	}
}

// The check tracks whether a string is in a name's position, so a value that
// happens to spell a field name is not a repeat. Getting this wrong would refuse
// honest documents, which is the worse failure of the two: it would make a
// sealed case unopenable.
func TestAValueThatSpellsANameIsNotARepeat(t *testing.T) {
	for name, document := range map[string]string{
		"a value equal to its own name":   `{"examiner":"examiner"}`,
		"a value equal to another name":   `{"examiner":"opened","opened":1}`,
		"a name appearing as a value too": `{"a":"b","b":"a"}`,
		"names in a string array":         `{"fields":["case_id","case_id"],"case_id":"C-1"}`,
	} {
		if err := RefuseRepeatedKeys([]byte(document), "the document"); err != nil {
			t.Errorf("%s was refused, and it holds no repeated name: %s\n  %s", name, document, err.Error())
		}
	}
}

// Two objects in one array are two objects. A check that kept one set of names
// for the whole document would refuse every manifest that lists more than one
// file, since each entry names "name" and "sha256".
func TestSeparateObjectsMayShareNames(t *testing.T) {
	manifest := []byte(`{"format":"x","files":[` +
		`{"name":"record.mrec","sha256":"aa"},` +
		`{"name":"grant.json","sha256":"bb"},` +
		`{"name":"proof.json","sha256":"cc"}],` +
		`"seal":{"manifest_hash":"dd","signature":"ee"}}`)

	if err := RefuseRepeatedKeys(manifest, "the disclosure manifest"); err != nil {
		t.Fatalf("a manifest listing three files was refused: %s", err.Error())
	}
}

// Nothing the encoder can write is refused. json.Marshal cannot emit a repeated
// name, so this check rejects no document Mutant has ever written -- which is
// the condition the fix was accepted under: the canonical form does not change
// and every manifest already sealed goes on verifying.
func TestTheShapesThisBuildWritesAreAccepted(t *testing.T) {
	for name, document := range map[string]string{
		"a scalar document":           `5`,
		"a string document":           `"text"`,
		"null":                        `null`,
		"an empty object":             `{}`,
		"an empty array":              `[]`,
		"an object of empties":        `{"a":{},"b":[],"c":null}`,
		"nested arrays of objects":    `[[{"a":1}],[{"a":2}]]`,
		"a realistic key file":        `{"format":"mutant-case-key","version":1,"kdf":{"algorithm":"argon2id","time":3},"generations":[{"index":0,"salt":"aa"},{"index":1,"salt":"bb"}]}`,
		"numbers that need UseNumber": `{"opened":1759881600,"size":18446744073709551615}`,
	} {
		if err := RefuseRepeatedKeys([]byte(document), "the document"); err != nil {
			t.Errorf("%s was refused: %s\n  %s", name, document, err.Error())
		}
	}
}

// This function answers one question. A malformed document and a document with
// a tail are the caller's Decode and RefuseTrailingContent's to report, each of
// which already words its message for the file it is reading. If this function
// reported them too, every malformed-file message in four readers would change
// wording for no reason, and a user chasing a truncated manifest would be told
// about field names.
func TestItReportsNothingButRepeatedNames(t *testing.T) {
	for name, document := range map[string]string{
		"empty input":            ``,
		"whitespace only":        `   `,
		"a truncated object":     `{"a":1`,
		"a bad escape":           `{"a":"\q"}`,
		"a stray closing brace":  `{"a":1}}`,
		"two documents":          `{"a":1}{"b":2}`,
		"a document then a tail": `{"a":1} trailing`,
		"not JSON at all":        `regf...binary...`,
	} {
		if err := RefuseRepeatedKeys([]byte(document), "the document"); err != nil {
			t.Errorf("%s was refused here rather than left to the caller: %s\n  %s",
				name, document, err.Error())
		}
	}
}

// A repeat before the malformed part is still reported: the walk reaches it
// first, and a document that repeats a name is refused whether or not it also
// fails to parse. The complement of the test above, so that "reports nothing
// but repeated names" is not read as "stays quiet whenever anything else is
// wrong too".
func TestARepeatBeforeAParseErrorIsStillReported(t *testing.T) {
	if err := RefuseRepeatedKeys([]byte(`{"a":1,"a":2,`), "the document"); err == nil {
		t.Fatal("a repeated name was accepted because the document was also truncated after it")
	}
}

// The message has to name the field and the thing being read, for the reason
// RefuseTrailingContent's doc comment gives: an examiner holding six files
// cannot act on "the file".
func TestTheRefusalSaysWhichNameAndWhichFile(t *testing.T) {
	err := RefuseRepeatedKeys([]byte(`{"case_id":"C-1","opened":1,"opened":2}`), "the grant file")
	if err == nil {
		t.Fatal("accepted a repeated name")
	}
	message := err.Error()
	for _, want := range []string{"the grant file", `"opened"`, "ends at byte"} {
		if !strings.Contains(message, want) {
			t.Errorf("the refusal does not say %s:\n  %s", want, message)
		}
	}
	if strings.Contains(message, `"case_id"`) {
		t.Errorf("the refusal names a field that is not repeated:\n  %s", message)
	}
}
