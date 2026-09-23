package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// buildRecord assembles a whole record in memory and returns its three parts.
//
// The real record_seal streams, because evidence does not fit in memory. This
// does not, because a test that holds the plaintext can assert things about it
// that a streaming one cannot -- and the parts it produces are byte-identical
// either way, which is what the tests below are actually about.
func buildRecord(t *testing.T, plaintext []byte, spans []RecordSpan, segmentSize uint32, sign bool) (
	header []byte, data []byte, footer []byte, keys *RecordKeys, cuid CaseUID, ruid RecordUID,
) {
	t.Helper()

	keys, cuid, ruid, _, sealSalt := mustKeysForSpans(t, spans, plaintext, segmentSize)

	h := &RecordHeader{
		Format:                 RecordFileFormat,
		Version:                RecordFileVersion,
		RecordUID:              hex.EncodeToString(ruid[:]),
		CaseUID:                hex.EncodeToString(cuid[:]),
		CaseKeyID:              "0123456789abcdef",
		SealedUnderGeneration:  1,
		WrappedUnderGeneration: 1,
		RecordKeyNonce:         strings.Repeat("00", 24),
		RecordKeyWrapped:       strings.Repeat("00", WrappedKeySize),
		SealSalt:               hex.EncodeToString(sealSalt),
		PlaintextLength:        uint64(len(plaintext)),
		SegmentSize:            segmentSize,
		Created:                "2026-09-23T00:00:00Z",
		Examiner:               "an asserted name",
		Spans:                  spans,
	}

	segments, err := h.Segments()
	if err != nil {
		t.Fatalf("deriving segments: %v", err)
	}

	digest := sha256.Sum256(plaintext)
	meta, _ := json.Marshal(RecordMeta{PlaintextSHA256: hex.EncodeToString(digest[:])})
	nonce, blob, err := keys.SealMeta(meta)
	if err != nil {
		t.Fatalf("sealing meta: %v", err)
	}
	sealedMeta := RecordSealedBlock{Nonce: hex.EncodeToString(nonce[:]), Blob: hex.EncodeToString(blob)}

	header, err = MarshalRecordHeader(h)
	if err != nil {
		t.Fatalf("marshalling header: %v", err)
	}

	digests := make([][sha256.Size]byte, 0, len(segments))
	for _, segment := range segments {
		aad, err := h.SegmentAAD(segment, uint64(len(segments)))
		if err != nil {
			t.Fatalf("segment %d aad: %v", segment.Index, err)
		}
		ct, d, err := keys.SealSegment(aad, plaintext[segment.Offset:segment.Offset+uint64(segment.Length)])
		if err != nil {
			t.Fatalf("sealing segment %d: %v", segment.Index, err)
		}
		data = append(data, ct...)
		digests = append(digests, d)
	}
	if !keys.SealComplete() {
		t.Fatalf("the record is not fully sealed: %d of %d", keys.SealedCount(), keys.Total())
	}

	f := &RecordFooter{SealedMeta: sealedMeta}
	if err := SignRecordFooter(f, header, SegmentsRoot(digests), sign); err != nil {
		t.Fatalf("signing: %v", err)
	}
	footer, err = MarshalRecordFooter(f)
	if err != nil {
		t.Fatalf("marshalling footer: %v", err)
	}
	return header, data, footer, keys, cuid, ruid
}

func mustKeysForSpans(t *testing.T, spans []RecordSpan, plaintext []byte, segmentSize uint32) (
	*RecordKeys, CaseUID, RecordUID, []byte, []byte,
) {
	t.Helper()
	counter := &RecordHeader{PlaintextLength: uint64(len(plaintext)), SegmentSize: segmentSize, Spans: spans}
	segments, err := counter.Segments()
	if err != nil {
		t.Fatalf("deriving segments: %v", err)
	}
	cuid, err := RandomCaseUID()
	if err != nil {
		t.Fatal(err)
	}
	ruid, err := RandomRecordUID()
	if err != nil {
		t.Fatal(err)
	}
	keys, rk, salt, err := NewRecordKeysForSeal(cuid, ruid, 1, uint64(len(segments)))
	if err != nil {
		t.Fatal(err)
	}
	return keys, cuid, ruid, rk, salt
}

// threeClasses is a plaintext of 200 bytes in three spans, with a segment size
// of 64 so that the middle span splits and the last one does not fill.
func threeClasses(t *testing.T) ([]byte, []RecordSpan) {
	t.Helper()
	tagKey := make([]byte, 32)
	for i := range tagKey {
		tagKey[i] = byte(i)
	}
	open, _ := TagForClass(tagKey, "open")
	restricted, _ := TagForClass(tagKey, "restricted")
	plaintext := make([]byte, 200)
	for i := range plaintext {
		plaintext[i] = byte('a' + i%26)
	}
	return plaintext, []RecordSpan{
		{Offset: 0, Length: 30, Class: hex.EncodeToString(open[:])},
		{Offset: 30, Length: 150, Class: hex.EncodeToString(restricted[:])},
		{Offset: 180, Length: 20, Class: hex.EncodeToString(open[:])},
	}
}

// A record verifies with no key at all. This is the property the whole format
// is arranged around.
func TestARecordVerifiesWithNoKey(t *testing.T) {
	plaintext, spans := threeClasses(t)
	header, data, footer, keys, _, _ := buildRecord(t, plaintext, spans, 64, true)
	keys.Zero()

	// From here on the test holds no key material of any kind: only the bytes a
	// recipient who was granted nothing would hold.
	parsed, err := ParseRecordHeader(header)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	segments, err := parsed.Segments()
	if err != nil {
		t.Fatalf("segments: %v", err)
	}
	if got := parsed.StoredDataSize(segments); got != uint64(len(data)) {
		t.Fatalf("the header describes %d bytes of segment data and there are %d", got, len(data))
	}

	root, err := rootFromStoredData(t, parsed, segments, data)
	if err != nil {
		t.Fatal(err)
	}
	parsedFooter, err := ParseRecordFooter(footer)
	if err != nil {
		t.Fatalf("parsing footer: %v", err)
	}
	signed, valid, detail := VerifyRecordSignature(parsedFooter, header, root)
	if !signed || !valid {
		t.Fatalf("a freshly sealed record does not verify: signed=%t valid=%t %s", signed, valid, detail)
	}
	t.Logf("verified holding nothing: %d segments over %d spans, %d bytes of data; %s",
		len(segments), len(spans), len(data), detail)

	// And the plaintext digest is NOT readable anywhere in the record, because a
	// digest published beside the ciphertext confirms any plaintext that can be
	// guessed -- which for a short or formulaic segment is the whole secret.
	clear := hex.EncodeToString(sha256Sum(plaintext))
	if strings.Contains(string(header), clear) || strings.Contains(string(footer), clear) {
		t.Fatal("the whole-plaintext digest is stored in the clear")
	}
}

// rootFromStoredData recomputes every segment digest from the ciphertext, the
// way a reader with no key does it.
func rootFromStoredData(t *testing.T, h *RecordHeader, segments []RecordSegment, data []byte) ([sha256.Size]byte, error) {
	t.Helper()
	digests := make([][sha256.Size]byte, 0, len(segments))
	for _, segment := range segments {
		aad, err := h.SegmentAAD(segment, uint64(len(segments)))
		if err != nil {
			return [sha256.Size]byte{}, err
		}
		encoded := aad.encode()
		sum := sha256.New()
		sum.Write(encoded[:])
		sum.Write(data[segment.StoredOffset : segment.StoredOffset+segment.StoredLength])
		var d [sha256.Size]byte
		copy(d[:], sum.Sum(nil))
		digests = append(digests, d)
	}
	return SegmentsRoot(digests), nil
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// Every way of editing a sealed record that does not touch the header must move
// the root, and therefore break the signature -- including the two that leave
// every surviving segment individually valid.
func TestEditingASealedRecordBreaksItsSignature(t *testing.T) {
	plaintext, spans := threeClasses(t)
	header, data, footer, keys, _, _ := buildRecord(t, plaintext, spans, 64, true)
	keys.Zero()
	parsed, _ := ParseRecordHeader(header)
	segments, _ := parsed.Segments()
	parsedFooter, _ := ParseRecordFooter(footer)

	edits := []struct {
		name string
		make func() []byte
	}{
		{"a flipped byte in a segment", func() []byte {
			edited := append([]byte(nil), data...)
			edited[0] ^= 1
			return edited
		}},
		{"the last segment dropped", func() []byte {
			last := segments[len(segments)-1]
			return append([]byte(nil), data[:last.StoredOffset]...)
		}},
		// Segments 1 and 2 are the two full ones inside the middle span, so
		// swapping them changes nothing about the file's shape -- same lengths,
		// same offsets, same classification. Only the order moves, and only the
		// root notices.
		{"two segments transposed", func() []byte {
			a, b := segments[1], segments[2]
			if a.StoredLength != b.StoredLength {
				t.Fatalf("the fixture changed: segments 1 and 2 are %d and %d bytes",
					a.StoredLength, b.StoredLength)
			}
			edited := append([]byte(nil), data...)
			copy(edited[a.StoredOffset:], data[b.StoredOffset:b.StoredOffset+b.StoredLength])
			copy(edited[b.StoredOffset:], data[a.StoredOffset:a.StoredOffset+a.StoredLength])
			return edited
		}},
	}
	for _, edit := range edits {
		t.Run(edit.name, func(t *testing.T) {
			edited := edit.make()
			// A dropped segment shortens the data, so recompute against whatever
			// segments the surviving bytes can supply -- which is the charitable
			// reading, and still has to fail.
			usable := segments
			if uint64(len(edited)) < parsed.StoredDataSize(segments) {
				usable = nil
				for _, segment := range segments {
					if segment.StoredOffset+segment.StoredLength <= uint64(len(edited)) {
						usable = append(usable, segment)
					}
				}
			}
			root, err := rootFromStoredData(t, parsed, usable, edited)
			if err != nil {
				t.Fatal(err)
			}
			_, valid, detail := VerifyRecordSignature(parsedFooter, header, root)
			if valid {
				t.Fatal("the edited record still verifies")
			}
			t.Logf("refused: %s", detail)
		})
	}
}

// The header is signed as the bytes that are stored, so any edit to it is an
// edit to the signed message.
func TestEditingTheHeaderBreaksTheSignature(t *testing.T) {
	plaintext, spans := threeClasses(t)
	header, data, footer, keys, _, _ := buildRecord(t, plaintext, spans, 64, true)
	keys.Zero()
	parsed, _ := ParseRecordHeader(header)
	segments, _ := parsed.Segments()
	parsedFooter, _ := ParseRecordFooter(footer)
	root, _ := rootFromStoredData(t, parsed, segments, data)

	if _, valid, _ := VerifyRecordSignature(parsedFooter, header, root); !valid {
		t.Fatal("the unedited record does not verify")
	}
	// The same length, so what breaks is the content and not the length prefix.
	edited := []byte(strings.Replace(string(header), "an asserted name", "a different name", 1))
	if len(edited) != len(header) {
		t.Fatalf("the test's edit changed the length: %d vs %d", len(edited), len(header))
	}
	if _, valid, detail := VerifyRecordSignature(parsedFooter, edited, root); valid {
		t.Fatal("a record whose examiner was rewritten still verifies")
	} else {
		t.Logf("refused: %s", detail)
	}
}

// A span list that does not partition the plaintext is refused, and the refusal
// says which shape it was.
func TestSpansMustPartitionThePlaintext(t *testing.T) {
	tagKey := make([]byte, 32)
	open, _ := TagForClass(tagKey, "open")
	tag := hex.EncodeToString(open[:])

	for _, tc := range []struct {
		name  string
		total uint64
		spans []RecordSpan
		want  string
	}{
		{"a gap", 100, []RecordSpan{
			{Offset: 0, Length: 40, Class: tag},
			{Offset: 50, Length: 50, Class: tag},
		}, "no gap and no overlap"},
		{"an overlap", 100, []RecordSpan{
			{Offset: 0, Length: 60, Class: tag},
			{Offset: 40, Length: 60, Class: tag},
		}, "no gap and no overlap"},
		{"an empty span", 100, []RecordSpan{
			{Offset: 0, Length: 0, Class: tag},
			{Offset: 0, Length: 100, Class: tag},
		}, "covers nothing"},
		{"an uncovered tail", 100, []RecordSpan{
			{Offset: 0, Length: 60, Class: tag},
		}, "unclassified tail"},
		{"a span past the end", 100, []RecordSpan{
			{Offset: 0, Length: 140, Class: tag},
		}, "past the"},
		{"no spans at all", 100, nil, "at least one"},
		{"a class tag that is not one", 100, []RecordSpan{
			{Offset: 0, Length: 100, Class: "not-a-tag"},
		}, "64 hex characters"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &RecordHeader{PlaintextLength: tc.total, SegmentSize: 64, Spans: tc.spans}
			_, err := h.Segments()
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
			t.Logf("refused: %v", err)
		})
	}
}

// Segments split at the segment size, within a span and never across one, so a
// segment key can never open bytes of two classifications.
func TestSegmentsNeverCrossASpanBoundary(t *testing.T) {
	plaintext, spans := threeClasses(t)
	h := &RecordHeader{PlaintextLength: uint64(len(plaintext)), SegmentSize: 64, Spans: spans}
	segments, err := h.Segments()
	if err != nil {
		t.Fatal(err)
	}
	// 30 -> 1 segment, 150 -> 3 (64+64+22), 20 -> 1.
	if len(segments) != 5 {
		t.Fatalf("200 bytes in spans of 30/150/20 at 64 bytes a segment is 5 segments, got %d", len(segments))
	}
	for _, segment := range segments {
		var within bool
		for _, span := range spans {
			if segment.Offset >= span.Offset && segment.Offset+uint64(segment.Length) <= span.Offset+span.Length {
				if hex.EncodeToString(segment.Class[:]) != span.Class {
					t.Fatalf("segment %d sits inside a span whose class it does not carry", segment.Index)
				}
				within = true
				break
			}
		}
		if !within {
			t.Fatalf("segment %d at %d+%d straddles a classification boundary, so its key would open "+
				"bytes of two classifications", segment.Index, segment.Offset, segment.Length)
		}
	}
	t.Logf("%d segments, none straddling a boundary", len(segments))
}

// A header carrying a field this build does not know is refused rather than
// read as far as it goes.
func TestAnUnknownHeaderFieldIsRefused(t *testing.T) {
	plaintext, spans := threeClasses(t)
	header, _, _, keys, _, _ := buildRecord(t, plaintext, spans, 64, false)
	keys.Zero()

	var raw map[string]any
	if err := json.Unmarshal(header, &raw); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"an unknown field", func(m map[string]any) { m["surprise"] = "hello" }, "surprise"},
		{"version 2", func(m map[string]any) { m["version"] = 2.0 }, "version 2"},
		{"another format", func(m map[string]any) { m["format"] = "mutant-something" }, "format"},
		{"generation 0", func(m map[string]any) { m["sealed_under_generation"] = 0.0 }, "numbered from 1"},
		{"a truncated record uid", func(m map[string]any) { m["record_uid"] = "00" }, "record's uid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copyOf := map[string]any{}
			_ = json.Unmarshal(header, &copyOf)
			tc.mutate(copyOf)
			out, _ := json.Marshal(copyOf)
			if _, err := ParseRecordHeader(out); err == nil {
				t.Fatal("accepted")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused for the wrong reason: %v", err)
			} else {
				t.Logf("refused: %v", err)
			}
		})
	}
}

// An unsigned record reports two bits, not one: it is not a forgery.
func TestAnUnsignedRecordIsNotAForgery(t *testing.T) {
	plaintext, spans := threeClasses(t)
	header, data, footer, keys, _, _ := buildRecord(t, plaintext, spans, 64, false)
	keys.Zero()
	parsed, _ := ParseRecordHeader(header)
	segments, _ := parsed.Segments()
	parsedFooter, _ := ParseRecordFooter(footer)
	root, _ := rootFromStoredData(t, parsed, segments, data)

	signed, valid, detail := VerifyRecordSignature(parsedFooter, header, root)
	if signed {
		t.Fatal("a record sealed with sign:false claims a signature")
	}
	if valid {
		t.Fatal("an unsigned record reports a valid signature")
	}
	if !strings.Contains(detail, "sign:false") {
		t.Fatalf("the detail does not say why there is no signature: %s", detail)
	}
	t.Logf("unsigned, and says so: %s", detail)
}

// The header's private block opens for the record it belongs to and no other.
func TestTheSealedMetaBelongsToOneRecord(t *testing.T) {
	plaintext, spans := threeClasses(t)
	_, _, footer, keys, cuid, ruid := buildRecord(t, plaintext, spans, 64, false)
	defer keys.Zero()
	parsed, err := ParseRecordFooter(footer)
	if err != nil {
		t.Fatal(err)
	}

	nonceBytes, _ := hex.DecodeString(parsed.SealedMeta.Nonce)
	nonce, err := XNonceFromSlice(nonceBytes)
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := hex.DecodeString(parsed.SealedMeta.Blob)

	opened, err2 := keys.OpenMeta(nonce, blob)
	if err2 != nil {
		t.Fatalf("the record cannot open its own meta: %v", err)
	}
	var meta RecordMeta
	if err := json.Unmarshal(opened, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.PlaintextSHA256 != hex.EncodeToString(sha256Sum(plaintext)) {
		t.Fatal("the sealed digest is not the plaintext's")
	}
	t.Logf("the case key holder can confirm the plaintext digest: %s", meta.PlaintextSHA256[:16])

	// Moved to another record identity, it does not open. The additional data is
	// rebuilt from the record, so this fails on the tag and not on a check
	// somebody could forget to write.
	other, err := RandomRecordUID()
	if err != nil {
		t.Fatal(err)
	}
	elsewhere, err := OpenRecordKeys(cuid, other, 1, keys.Total(), make([]byte, KeySize), make([]byte, SealSaltSize))
	if err != nil {
		t.Fatal(err)
	}
	defer elsewhere.Zero()
	if _, err := elsewhere.OpenMeta(nonce, blob); err == nil {
		t.Fatal("the meta block opened under another record's identity")
	}
	_ = ruid
}

// The prefix bounds a header length before anything allocates for it.
func TestTheFilePrefixRefusesWhatItCannotBe(t *testing.T) {
	good := RecordFilePrefix(1234)
	length, err := ParseRecordFilePrefix(good)
	if err != nil || length != 1234 {
		t.Fatalf("a good prefix gave %d, %v", length, err)
	}
	for _, tc := range []struct {
		name   string
		prefix []byte
	}{
		{"too short", good[:4]},
		{"not a record", append([]byte("NOTAMREC"), good[8:]...)},
		{"a zero-length header", RecordFilePrefix(0)},
		{"a header larger than the bound", RecordFilePrefix(MaxRecordHeader + 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseRecordFilePrefix(tc.prefix); err == nil {
				t.Fatal("accepted")
			} else {
				t.Logf("refused: %v", err)
			}
		})
	}
}
