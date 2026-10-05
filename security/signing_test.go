package security

import (
	"strings"
	"testing"
)

// signatureWith builds an encoded signature whose timestamp field is given
// verbatim, so a malformed field can be handed to the decoder without going
// through Encode first.
func signatureWith(timestampField string) string {
	return strings.Join([]string{
		signingAlgorithmEd25519,
		"aabb",
		"ccdd",
		"322e362e30", // "2.6.0"
		timestampField,
	}, SEPERATOR)
}

// TestASignatureTimestampSurvivesTheRoundTrip is M26-SEC-009's fixture for the
// half of the defect the external report did not reach. Encode wrote the
// timestamp as string(rune(cs.Timestamp)) -- a Unicode code point, not a
// number. Every Unix timestamp since 1970-01-13 is larger than the largest
// valid code point, so the conversion yielded U+FFFD, the field encoded as
// efbfbd whatever the time was, and the decoder's one-byte read returned 239.
// On the unfixed code every case past 127 fails here.
func TestASignatureTimestampSurvivesTheRoundTrip(t *testing.T) {
	for _, ts := range []int64{
		0,
		1,
		127,        // the largest value the old one-byte read could carry
		128,        // the first it could not
		1114111,    // the largest valid Unicode code point
		1114112,    // one past it, where string(rune(...)) becomes U+FFFD
		1600000000, // 2020-09-13, an ordinary timestamp
		1791229312, // 2026
		1 << 62,
		-1, // a signed timestamp must survive too
	} {
		cs := &CodeSignature{
			Algorithm: signingAlgorithmEd25519,
			PublicKey: []byte{0xAA, 0xBB},
			Signature: []byte{0xCC, 0xDD},
			Version:   "2.6.0",
			Timestamp: ts,
		}
		back, err := DecodeSignature(cs.Encode())
		if err != nil {
			t.Errorf("timestamp %d: DecodeSignature after Encode: %v", ts, err)
			continue
		}
		if back.Timestamp != ts {
			t.Errorf("timestamp %d round-tripped as %d", ts, back.Timestamp)
		}
	}
}

// TestASignatureRoundTripsEveryFieldItCarries holds the rest of the pair to the
// same standard, so a later change to the encoding cannot quietly drop a field
// while the timestamp keeps working.
func TestASignatureRoundTripsEveryFieldItCarries(t *testing.T) {
	want := &CodeSignature{
		Algorithm: signingAlgorithmEd25519,
		PublicKey: []byte{0x01, 0x02, 0x03, 0xFF},
		Signature: []byte{0xDE, 0xAD, 0xBE, 0xEF},
		Version:   "2.6.0-rc1",
		Timestamp: 1791229312,
	}
	got, err := DecodeSignature(want.Encode())
	if err != nil {
		t.Fatalf("DecodeSignature after Encode: %v", err)
	}
	if got.Algorithm != want.Algorithm {
		t.Errorf("algorithm = %q, want %q", got.Algorithm, want.Algorithm)
	}
	if string(got.PublicKey) != string(want.PublicKey) {
		t.Errorf("public key = %x, want %x", got.PublicKey, want.PublicKey)
	}
	if string(got.Signature) != string(want.Signature) {
		t.Errorf("signature = %x, want %x", got.Signature, want.Signature)
	}
	if got.Version != want.Version {
		t.Errorf("version = %q, want %q", got.Version, want.Version)
	}
	if got.Timestamp != want.Timestamp {
		t.Errorf("timestamp = %d, want %d", got.Timestamp, want.Timestamp)
	}
}

// TestDecodeSignatureRefusesAMalformedTimestamp is M26-SEC-009's fixture for
// the half the external report did report. DecodeSignature read
// timestampBytes[0] with no length check, so a signature whose timestamp field
// was absent panicked with an index out of range -- out of a decoder whose
// entire input is untrusted text.
//
// The recover is deliberate. An unrecovered panic takes the whole package's
// test binary down with it, and that would hide every other result in this
// package behind one failure.
func TestDecodeSignatureRefusesAMalformedTimestamp(t *testing.T) {
	for _, c := range []struct {
		name  string
		field string
	}{
		{"absent", ""},
		{"one byte", "ef"},
		{"seven bytes", "00000000000000"},
		{"nine bytes", "000000000000000000"},
		{"not hex", "zz"},
	} {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("DecodeSignature panicked on a %s timestamp field: %v", c.name, r)
				}
			}()
			if _, err := DecodeSignature(signatureWith(c.field)); err == nil {
				t.Errorf("DecodeSignature accepted a %s timestamp field", c.name)
			}
		})
	}
}

// TestDecodeSignatureRefusesTheWrongNumberOfFields keeps the existing part-count
// refusal under test, since the timestamp check now sits behind it.
func TestDecodeSignatureRefusesTheWrongNumberOfFields(t *testing.T) {
	for _, enc := range []string{
		"",
		signingAlgorithmEd25519,
		strings.Join([]string{signingAlgorithmEd25519, "aabb", "ccdd", "322e362e30"}, SEPERATOR),
		strings.Join([]string{signingAlgorithmEd25519, "aabb", "ccdd", "322e362e30", "0000000000000000", "extra"}, SEPERATOR),
	} {
		if _, err := DecodeSignature(enc); err == nil {
			t.Errorf("DecodeSignature accepted %d fields", strings.Count(enc, SEPERATOR)+1)
		}
	}
}
