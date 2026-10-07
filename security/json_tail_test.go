package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A rewrite interrupted between the truncate and the write leaves padding, and
// a parser that refused it would turn a survivable crash into a lost case key.
// So these have to keep opening.
var acceptedTails = []struct{ name, tail string }{
	{"nothing at all", ""},
	{"one newline", "\n"},
	{"one crlf", "\r\n"},
	{"spaces, tabs and both endings", "  \t\r\n \n"},
}

// Every shape of trailing content. The four marked (More) are the ones the
// three parsers that already checked for a tail accepted anyway, because
// json.Decoder.More() is defined as `err == nil && c != ']' && c != '}'` and so
// reports nothing-more-to-read in front of a closing delimiter -- after which
// no byte of the rest of the file is examined at all.
var refusedTails = []struct{ name, tail string }{
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

func TestRefuseTrailingContentTakesWhitespaceAndNothingElse(t *testing.T) {
	const doc = `{"format":"mutant-test"}`
	read := func(data string) error {
		decoder := json.NewDecoder(strings.NewReader(data))
		var v map[string]any
		if err := decoder.Decode(&v); err != nil {
			t.Fatalf("the document itself did not parse: %v", err)
		}
		return RefuseTrailingContent(decoder, "the document")
	}
	for _, c := range acceptedTails {
		if err := read(doc + c.tail); err != nil {
			t.Errorf("%s: refused, and trailing whitespace has to parse: %v", c.name, err)
		}
	}
	ends := fmt.Sprintf("byte %d", len(doc))
	for _, c := range refusedTails {
		err := read(doc + c.tail)
		if err == nil {
			t.Errorf("%s: ACCEPTED", c.name)
			continue
		}
		// The offset is the point of the message: an examiner holding a file
		// that will not open needs to be told where to look in it.
		if !strings.Contains(err.Error(), ends) {
			t.Errorf("%s: the message does not say the document ends at %s: %v", c.name, ends, err)
		}
		t.Logf("%-62s refused: %.105s", c.name, err.Error())
	}
}

// The tails decoder.More() let through. This is the test the three parsers that
// already checked for a tail did not have, which is why the gap survived them.
// It asserts the gap is real as well as closed: if More() ever starts reporting
// these, the comment in json_tail.go explaining why Token() is used instead has
// become wrong and should be corrected rather than left to mislead.
func TestTheTailsDecoderMoreLetThrough(t *testing.T) {
	const doc = `{"format":"mutant-test"}`
	for _, tail := range []string{"}", "]", "} and 4 KiB of anything at all", "\n}\n{\"format\":\"second\"}"} {
		decode := func(data string) *json.Decoder {
			decoder := json.NewDecoder(strings.NewReader(data))
			var v map[string]any
			if err := decoder.Decode(&v); err != nil {
				t.Fatalf("%q: the document itself did not parse: %v", tail, err)
			}
			return decoder
		}
		if decode(doc + tail).More() {
			t.Errorf("%q: More() now reports this tail, so json_tail.go's explanation of why it is "+
				"not enough is out of date", tail)
		}
		if err := RefuseTrailingContent(decode(doc+tail), "the document"); err == nil {
			t.Errorf("%q: ACCEPTED", tail)
		}
	}
}

func TestACaseKeyFileRefusesWhatFollowsIt(t *testing.T) {
	pass := []byte("pp")
	cuid, err := RandomCaseUID()
	if err != nil {
		t.Fatal(err)
	}
	f, caseKey, err := NewCaseKeyFile(pass, cuid, "IR-TAIL", time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	SecureZero(caseKey)
	salt, _ := f.SaltBytes()
	wrapKey, err := DeriveWrappingKey(pass, salt, f.Version)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := SealCaseKeyFile(f, wrapKey, false); err != nil {
		t.Fatal(err)
	}
	SecureZero(wrapKey)
	document, err := MarshalCaseKeyFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCaseKeyFile(document); err != nil {
		t.Fatalf("the key file this test builds does not parse, so it proves nothing: %v", err)
	}
	for _, c := range acceptedTails {
		if _, err := ParseCaseKeyFile(withTail(document, c.tail)); err != nil {
			t.Errorf("a key file and then %s: refused, and a crash mid-rewrite leaves exactly that: %v", c.name, err)
		}
	}
	for _, c := range refusedTails {
		if _, err := ParseCaseKeyFile(withTail(document, c.tail)); err == nil {
			t.Errorf("a key file and then %s: ACCEPTED", c.name)
		}
	}
}

func TestARecordHeaderAndFooterRefuseWhatFollowsThem(t *testing.T) {
	plaintext, spans := threeClasses(t)
	header, _, footer, keys, _, _ := buildRecord(t, plaintext, spans, 64, true)
	keys.Zero()
	for _, c := range acceptedTails {
		if _, err := ParseRecordHeader(withTail(header, c.tail)); err != nil {
			t.Errorf("a header and then %s: %v", c.name, err)
		}
		if _, err := ParseRecordFooter(withTail(footer, c.tail)); err != nil {
			t.Errorf("a footer and then %s: %v", c.name, err)
		}
	}
	for _, c := range refusedTails {
		if _, err := ParseRecordHeader(withTail(header, c.tail)); err == nil {
			t.Errorf("a header and then %s: ACCEPTED", c.name)
		}
		if _, err := ParseRecordFooter(withTail(footer, c.tail)); err == nil {
			t.Errorf("a footer and then %s: ACCEPTED", c.name)
		}
	}
}

func TestAGrantFileRefusesWhatFollowsIt(t *testing.T) {
	fixture := newGrantFixture(t)
	grant, err := fixture.opener.IssueGrant(fixture.descriptorsOf(t, "open"))
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Zero()
	raw, err := MarshalGrantFile(grantFileFor(t, grant, bytes.Repeat([]byte{9}, KeySize)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGrantFile(raw); err != nil {
		t.Fatalf("the grant file this test builds does not parse, so it proves nothing: %v", err)
	}
	for _, c := range acceptedTails {
		if _, err := ParseGrantFile(withTail(raw, c.tail)); err != nil {
			t.Errorf("a grant file and then %s: %v", c.name, err)
		}
	}
	for _, c := range refusedTails {
		if _, err := ParseGrantFile(withTail(raw, c.tail)); err == nil {
			t.Errorf("a grant file and then %s: ACCEPTED", c.name)
		}
	}
}

// The whitespace half of the row taken all the way: not merely that a padded
// key file parses, but that it still authenticates and still opens. The row
// says "trailing whitespace also parses, and must: an interrupted rewrite
// leaves it", and a parse that produced a file nothing could open afterwards
// would satisfy the letter of that and none of the point.
//
// signed is tested as a condition and not asserted, the way
// record_crypto_test.go treats it: a machine with no key store writes an
// unsigned file, which is a documented mode and not a failure.
func TestAPaddedCaseKeyFileStillOpens(t *testing.T) {
	pass := []byte("correct horse battery staple")
	cuid, err := RandomCaseUID()
	if err != nil {
		t.Fatal(err)
	}
	f, caseKey, err := NewCaseKeyFile(pass, cuid, "IR-TAIL-OPEN",
		time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	defer SecureZero(caseKey)
	salt, err := f.SaltBytes()
	if err != nil {
		t.Fatal(err)
	}
	wrapKey, err := DeriveWrappingKey(pass, salt, f.Version)
	if err != nil {
		t.Fatal(err)
	}
	defer SecureZero(wrapKey)
	if _, _, err := SealCaseKeyFile(f, wrapKey, true); err != nil {
		t.Fatal(err)
	}
	document, err := MarshalCaseKeyFile(f)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range acceptedTails {
		parsed, err := ParseCaseKeyFile(withTail(document, c.tail))
		if err != nil {
			t.Fatalf("a key file and then %s: %v", c.name, err)
		}
		if parsed.CaseID != "IR-TAIL-OPEN" {
			t.Fatalf("a key file and then %s: case_id came back %q", c.name, parsed.CaseID)
		}
		if err := VerifyCaseKeyFile(parsed, wrapKey); err != nil {
			t.Fatalf("a key file and then %s: the file MAC no longer verifies: %v", c.name, err)
		}
		if signed, valid, detail := VerifyCaseKeyFileSignature(parsed); signed && !valid {
			t.Fatalf("a key file and then %s: the signature no longer holds: %s", c.name, detail)
		}
		opened, wk, err := OpenCaseKeyFile(parsed, pass, 0)
		if err != nil {
			t.Fatalf("a key file and then %s: the case key no longer opens: %v", c.name, err)
		}
		if !bytes.Equal(opened, caseKey) {
			t.Fatalf("a key file and then %s: the case key that came back is not the one the file holds", c.name)
		}
		SecureZero(opened)
		SecureZero(wk)
	}
}

// withTail copies rather than appending in place, because append on a slice
// with spare capacity would write the tail into the document every later case
// reads.
func withTail(document []byte, tail string) []byte {
	out := make([]byte, 0, len(document)+len(tail))
	out = append(out, document...)
	return append(out, tail...)
}
