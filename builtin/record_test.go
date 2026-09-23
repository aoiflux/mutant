package builtin

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// recordTestCase opens a case, mints and opens a key, and declares the two
// labels every test below uses.
func recordTestCase(t *testing.T) {
	t.Helper()
	openTestCase(t, "IR-REC", "examiner")
	t.Cleanup(resetRecordsForTesting)
	stubPassphrase(t, "correct horse battery staple")
	key := filepath.Join(t.TempDir(), "case.mkey")
	mustHash(t, CaseKeyCreate(stringObj(key)))
	mustHash(t, CaseKeyOpen(stringObj(key)))
	mustHash(t, ClassDefine(stringObj("open")))
	mustHash(t, ClassDefine(stringObj("restricted")))
}

// recordFixture writes 200 bytes of source and returns both paths.
func recordFixture(t *testing.T) (source, dest string, plaintext []byte) {
	t.Helper()
	dir := t.TempDir()
	source = filepath.Join(dir, "evidence.bin")
	dest = filepath.Join(dir, "evidence.mrec")
	plaintext = make([]byte, 200)
	for i := range plaintext {
		plaintext[i] = byte('a' + i%26)
	}
	if err := os.WriteFile(source, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resetRecordsForTesting)
	return source, dest, plaintext
}

func recordSealOpts(pairs map[string]object.Object) object.Object {
	base := map[string]object.Object{
		"default":      stringObj("open"),
		"segment_size": intObj(64),
		"sign":         boolObj(false),
	}
	for key, value := range pairs {
		base[key] = value
	}
	return makeHashObject(base)
}

func recordArray(values ...object.Object) object.Object {
	return &object.Array{Elements: values}
}

func recordBytes(t *testing.T, value object.Object) []byte {
	t.Helper()
	buffer, ok := value.(*object.Bytes)
	if !ok {
		t.Fatalf("expected BYTES, got %T", value)
	}
	return buffer.Value
}

// The whole cycle: classify, seal, verify with no key, open, read, close.
func TestARecordSealsOpensAndReadsBack(t *testing.T) {
	recordTestCase(t)
	source, dest, plaintext := recordFixture(t)

	restricted := mustHash(t, RecordClassifyRange(intObj(30), intObj(150), stringObj("restricted")))
	sealed := mustHash(t, RecordSeal(stringObj(source), stringObj(dest),
		recordArray(restricted), recordSealOpts(nil)))

	if got := mustHashValue(t, sealed, "segments").Inspect(); got != "5" {
		t.Fatalf("200 bytes in spans of 30/150/20 at 64 bytes a segment is 5 segments, got %s", got)
	}
	if got := mustHashValue(t, sealed, "plaintext_length").Inspect(); got != "200" {
		t.Fatalf("plaintext_length is %s", got)
	}

	// Verified with no case key involved: this is the property a recipient who
	// was granted nothing still has.
	verified := mustHash(t, RecordVerify(stringObj(dest)))
	if !mustHashBoolValue(t, verified, "verified_without_key") {
		t.Fatal("record_verify does not report that it needed no key")
	}
	if _, present := hashLookup(verified, "does_not_prove"); !present {
		t.Fatal("record_verify does not say what it did not establish")
	}

	opened := mustHash(t, RecordOpen(stringObj(dest)))
	handle := mustHashValue(t, opened, "handle")
	defer RecordClose(handle)

	whole := recordBytes(t, mustValue(t, RecordRead(handle, intObj(0), intObj(200))))
	if !bytes.Equal(whole, plaintext) {
		t.Fatal("the record does not read back as the evidence that was sealed")
	}
	// A span that crosses two segments and starts inside the first.
	part := recordBytes(t, mustValue(t, RecordRead(handle, intObj(50), intObj(40))))
	if !bytes.Equal(part, plaintext[50:90]) {
		t.Fatalf("a cross-segment read gave %q", part)
	}
	t.Logf("sealed %d bytes into %s segments and read every one back",
		len(plaintext), mustHashValue(t, sealed, "segments").Inspect())

	if _, errObj := unwrapPairNoFatal(RecordClose(handle)); errObj != nil {
		t.Fatalf("close: %s", errObj.Message)
	}
	if _, errObj := unwrapPairNoFatal(RecordLayout(handle)); errObj == nil {
		t.Fatal("a closed handle still resolves")
	}
}

// mustValue unwraps a (value, err) pair and fails on the error half.
func mustValue(t *testing.T, result object.Object) object.Object {
	t.Helper()
	value, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("call failed: %s", errObj.Message)
	}
	return value
}

// Every byte carries a class, and the one covering what no range named is
// chosen by the examiner rather than by the implementation.
func TestSealingRequiresADefaultClass(t *testing.T) {
	recordTestCase(t)
	source, dest, _ := recordFixture(t)

	_, errObj := unwrapPairNoFatal(RecordSeal(stringObj(source), stringObj(dest),
		recordArray(), makeHashObject(map[string]object.Object{"sign": boolObj(false)})))
	if errObj == nil {
		t.Fatal("a seal with no default class was accepted")
	}
	if !strings.Contains(errObj.Message, "no implicit unclassified") {
		t.Fatalf("the refusal does not say why: %s", errObj.Message)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("the refused seal left a file behind")
	}
	t.Logf("refused: %s", errObj.Message)
}

// A label nobody declared is refused at the line that named it.
func TestAnUndeclaredLabelIsRefusedWhereItIsWritten(t *testing.T) {
	recordTestCase(t)
	_, errObj := unwrapPairNoFatal(RecordClassifyRange(intObj(0), intObj(10), stringObj("ultra-secret")))
	if errObj == nil {
		t.Fatal("an undeclared label was accepted")
	}
	if !strings.Contains(errObj.Message, "not a declared classification") {
		t.Fatalf("refused for the wrong reason: %s", errObj.Message)
	}
	// And the refusal names what IS declared, so the fix does not need a second
	// call to find out.
	if !strings.Contains(errObj.Message, "restricted") {
		t.Fatalf("the refusal does not name the declared classes: %s", errObj.Message)
	}
	t.Logf("refused: %s", errObj.Message)
}

// Overlapping ranges are refused rather than resolved.
func TestOverlappingRangesAreRefused(t *testing.T) {
	recordTestCase(t)
	source, dest, _ := recordFixture(t)

	first := mustHash(t, RecordClassifyRange(intObj(0), intObj(100), stringObj("restricted")))
	second := mustHash(t, RecordClassifyRange(intObj(60), intObj(100), stringObj("open")))
	_, errObj := unwrapPairNoFatal(RecordSeal(stringObj(source), stringObj(dest),
		recordArray(first, second), recordSealOpts(nil)))
	if errObj == nil {
		t.Fatal("two overlapping ranges were accepted")
	}
	if !strings.Contains(errObj.Message, "legal question") {
		t.Fatalf("the refusal does not say why it will not choose: %s", errObj.Message)
	}
	t.Logf("refused: %s", errObj.Message)
}

// A record is never written over.
func TestARecordIsNeverWrittenOver(t *testing.T) {
	recordTestCase(t)
	source, dest, _ := recordFixture(t)

	mustHash(t, RecordSeal(stringObj(source), stringObj(dest), recordArray(), recordSealOpts(nil)))
	before, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	_, errObj := unwrapPairNoFatal(RecordSeal(stringObj(source), stringObj(dest),
		recordArray(), recordSealOpts(nil)))
	if errObj == nil {
		t.Fatal("a second seal wrote over the first record")
	}
	after, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the refused seal changed the record it refused to replace")
	}
	t.Logf("refused: %s", errObj.Message)
}

// record_read refuses a span it cannot fully decrypt; record_read_partial is
// the separate contract that hands back what there is.
func TestAReadThatCannotCompleteIsAnErrorAndPartialIsSeparate(t *testing.T) {
	recordTestCase(t)
	source, dest, plaintext := recordFixture(t)
	mustHash(t, RecordSeal(stringObj(source), stringObj(dest), recordArray(), recordSealOpts(nil)))

	// Find where segment 1 is stored, then flip a byte inside it. The tamper is
	// on disk, not in the API: what is being tested is that a segment which
	// fails its Poly1305 tag is reported and not quietly zero-filled.
	opened := mustHash(t, RecordOpen(stringObj(dest)))
	handle := mustHashValue(t, opened, "handle")
	layout := mustHash(t, RecordLayout(handle))
	segments, ok := mustHashValue(t, layout, "segments").(*object.Array)
	if !ok || len(segments.Elements) < 2 {
		t.Fatal("the fixture should have several segments")
	}
	second, _ := segments.Elements[1].(*object.Hash)
	storedAt := mustHashValue(t, second, "stored_offset").(*object.Integer).Value
	holeFrom := mustHashValue(t, second, "offset").(*object.Integer).Value
	holeLen := mustHashValue(t, second, "length").(*object.Integer).Value
	mustValue(t, RecordClose(handle))

	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	raw[storedAt] ^= 1
	if err := os.WriteFile(dest, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	opened = mustHash(t, RecordOpen(stringObj(dest)))
	handle = mustHashValue(t, opened, "handle")
	defer RecordClose(handle)

	_, errObj := unwrapPairNoFatal(RecordRead(handle, intObj(0), intObj(int64(len(plaintext)))))
	if errObj == nil {
		t.Fatal("a read across a segment that does not open returned bytes")
	}
	if !strings.Contains(errObj.Message, "record_read_partial") {
		t.Fatalf("the refusal does not point at the other contract: %s", errObj.Message)
	}
	t.Logf("record_read refused: %s", errObj.Message)

	partial := mustHash(t, RecordReadPartial(handle, intObj(0), intObj(int64(len(plaintext)))))
	if mustHashBoolValue(t, partial, "complete") {
		t.Fatal("record_read_partial reports a complete read over a broken segment")
	}
	if got := mustHashValue(t, partial, "withheld").(*object.Integer).Value; got != holeLen {
		t.Fatalf("withheld is %d, want the %d bytes of the broken segment", got, holeLen)
	}
	holes, ok := mustHashValue(t, partial, "holes").(*object.Array)
	if !ok || len(holes.Elements) != 1 {
		t.Fatalf("holes is %v", mustHashValue(t, partial, "holes").Inspect())
	}
	hole, _ := holes.Elements[0].(*object.Hash)
	if got := mustHashValue(t, hole, "offset").(*object.Integer).Value; got != holeFrom {
		t.Fatalf("the hole is reported at %d and the segment starts at %d", got, holeFrom)
	}

	// The readable bytes are still the evidence, and the hole is zeros at
	// exactly the right offsets -- which is what lets a caller line the rest up.
	got := recordBytes(t, mustHashValue(t, partial, "bytes"))
	if len(got) != len(plaintext) {
		t.Fatalf("the partial read is %d bytes, want %d", len(got), len(plaintext))
	}
	if !bytes.Equal(got[:holeFrom], plaintext[:holeFrom]) {
		t.Fatal("the bytes before the hole are not the evidence")
	}
	if !bytes.Equal(got[holeFrom+holeLen:], plaintext[holeFrom+holeLen:]) {
		t.Fatal("the bytes after the hole are not at their true offsets")
	}
	for _, b := range got[holeFrom : holeFrom+holeLen] {
		if b != 0 {
			t.Fatal("the hole is not zero-filled")
		}
	}
	t.Logf("partial read: %d bytes with a %d-byte hole at %d, the rest in place",
		len(got), holeLen, holeFrom)
}

// Quantising rounds outward, says by how much, and refuses to merge two
// classes on its own authority.
func TestQuantisingRoundsOutwardAndSaysByHowMuch(t *testing.T) {
	recordTestCase(t)
	source, dest, _ := recordFixture(t)

	// 4 bytes at offset 34, rounded to a 16-byte quantum, becomes 32..48.
	short := mustHash(t, RecordClassifyRange(intObj(34), intObj(4), stringObj("restricted")))
	sealed := mustHash(t, RecordSealQuantised(stringObj(source), stringObj(dest),
		recordArray(short), recordSealOpts(map[string]object.Object{
			"quantum": intObj(16),
			// The default here is `open`, so growing `restricted` over it
			// withholds more. That is the direction quantising was designed
			// for, and naming it is what makes the direction a decision rather
			// than an accident -- see TestQuantisingWillNotGrowAClassNobodyNamed.
			"rounds_to": stringObj("restricted"),
		})))

	extra := mustHashValue(t, sealed, "quantised_extra").(*object.Integer).Value
	if extra != 12 {
		t.Fatalf("rounding 34+4 out to a 16-byte quantum moves 12 extra bytes, reported %d", extra)
	}
	if got := mustHashStringValue(t, sealed, "rounds_to"); got != "restricted" {
		t.Fatalf("the record says rounding grew %q, want restricted", got)
	}
	spans, _ := mustHashValue(t, sealed, "spans").(*object.Array)
	var found bool
	for _, element := range spans.Elements {
		span, _ := element.(*object.Hash)
		offset := mustHashValue(t, span, "offset").(*object.Integer).Value
		length := mustHashValue(t, span, "length").(*object.Integer).Value
		if offset == 32 && length == 16 {
			found = true
		}
	}
	if !found {
		t.Fatalf("the rounded span is not 32+16 in %s", mustHashValue(t, sealed, "spans").Inspect())
	}
	t.Logf("a 4-byte secret at 34 became a 16-byte span at 32; %d extra bytes withheld and recorded", extra)
}

func TestQuantisingWillNotMergeTwoClasses(t *testing.T) {
	recordTestCase(t)
	source, dest, _ := recordFixture(t)

	first := mustHash(t, RecordClassifyRange(intObj(10), intObj(4), stringObj("restricted")))
	second := mustHash(t, RecordClassifyRange(intObj(20), intObj(4), stringObj("open")))
	_, errObj := unwrapPairNoFatal(RecordSealQuantised(stringObj(source), stringObj(dest),
		recordArray(first, second), recordSealOpts(map[string]object.Object{
			"quantum": intObj(64), "rounds_to": stringObj("restricted"),
		})))
	if errObj == nil {
		t.Fatal("rounding merged two classifications without asking")
	}
	// Both ranges fall inside one 64-byte quantum, so both would be widened,
	// and only one class was named. The refusal names the range that was not.
	if !strings.Contains(errObj.Message, "would widen the range at 20+4") {
		t.Fatalf("the refusal does not say which range it would not round: %s", errObj.Message)
	}
	t.Logf("refused: %s", errObj.Message)
}

// A citation of one segment reveals nothing about what the segment holds.
func TestASegmentCitationIsContentFree(t *testing.T) {
	recordTestCase(t)
	source, dest, plaintext := recordFixture(t)
	restricted := mustHash(t, RecordClassifyRange(intObj(64), intObj(64), stringObj("restricted")))
	mustHash(t, RecordSeal(stringObj(source), stringObj(dest),
		recordArray(restricted), recordSealOpts(nil)))

	opened := mustHash(t, RecordOpen(stringObj(dest)))
	handle := mustHashValue(t, opened, "handle")
	defer RecordClose(handle)

	citation := mustHash(t, RecordProveSegment(handle, intObj(1)))
	if !mustHashBoolValue(t, citation, "content_free") {
		t.Fatal("the citation does not claim to be content-free")
	}
	if !mustHashBoolValue(t, citation, "root_matches") {
		t.Fatal("an untouched record does not fold to the root its footer names")
	}
	if _, present := hashLookup(citation, "does_not_prove"); !present {
		t.Fatal("the citation does not say what it fails to establish")
	}
	// Nothing in the rendered citation is any run of the plaintext.
	rendered := citation.Inspect()
	for start := 0; start+8 <= len(plaintext); start += 8 {
		if strings.Contains(rendered, string(plaintext[start:start+8])) {
			t.Fatalf("the citation contains plaintext from offset %d", start)
		}
	}
	t.Logf("segment %s at %s+%s cited with no plaintext in it",
		mustHashValue(t, citation, "segment").Inspect(),
		mustHashValue(t, citation, "offset").Inspect(),
		mustHashValue(t, citation, "length").Inspect())
}

// A record belongs to the case that sealed it.
func TestARecordIsRefusedByACaseItDoesNotBelongTo(t *testing.T) {
	recordTestCase(t)
	source, dest, _ := recordFixture(t)
	mustHash(t, RecordSeal(stringObj(source), stringObj(dest), recordArray(), recordSealOpts(nil)))

	// A second case, with a key of its own, is a different case uid.
	resetCustodyForTesting()
	openTestCase(t, "IR-OTHER", "examiner")
	stubPassphrase(t, "a different passphrase entirely")
	other := filepath.Join(t.TempDir(), "other.mkey")
	mustHash(t, CaseKeyCreate(stringObj(other)))
	mustHash(t, CaseKeyOpen(stringObj(other)))

	_, errObj := unwrapPairNoFatal(RecordOpen(stringObj(dest)))
	if errObj == nil {
		t.Fatal("a record opened under a case that did not seal it")
	}
	if !strings.Contains(errObj.Message, "bound to the case") {
		t.Fatalf("refused for the wrong reason: %s", errObj.Message)
	}
	t.Logf("refused: %s", errObj.Message)
}

// The claim DISCLOSURE_POLICY.md section 4 makes about the footer, checked
// rather than asserted: a segment changed by anybody makes the record stop
// folding to the root its own footer names, and record_verify says so holding
// no key.
//
// This is the whole of what the footer buys. A per-segment tag cannot see it --
// every other segment is still individually valid -- so if this test fails, the
// policy is making a promise the tree does not keep.
func TestATamperedSegmentBreaksASignedRecord(t *testing.T) {
	recordTestCase(t)
	source, dest, _ := recordFixture(t)
	sealed := mustHash(t, RecordSeal(stringObj(source), stringObj(dest), recordArray(),
		recordSealOpts(map[string]object.Object{"sign": boolObj(true)})))
	if !mustHashBoolValue(t, sealed, "signed") {
		t.Skip("this machine has no key store, so there is no signature to break")
	}

	before := mustHash(t, RecordVerify(stringObj(dest)))
	if !mustHashBoolValue(t, before, "signature_valid") {
		t.Fatalf("a freshly sealed record does not verify: %s", keyFieldString(t, before, "signature_note"))
	}

	// One byte, inside the segment data area, well past the header.
	opened := mustHash(t, RecordOpen(stringObj(dest)))
	handle := mustHashValue(t, opened, "handle")
	layout := mustHash(t, RecordLayout(handle))
	segments, _ := mustHashValue(t, layout, "segments").(*object.Array)
	last, _ := segments.Elements[len(segments.Elements)-1].(*object.Hash)
	at := mustHashValue(t, last, "stored_offset").(*object.Integer).Value
	mustValue(t, RecordClose(handle))

	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	raw[at] ^= 1
	if err := os.WriteFile(dest, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	after := mustHash(t, RecordVerify(stringObj(dest)))
	if !mustHashBoolValue(t, after, "signed") {
		t.Fatal("the tampered record no longer claims to be signed, which hides the tamper")
	}
	if mustHashBoolValue(t, after, "signature_valid") {
		t.Fatal("a record with a changed segment still verifies; the footer buys nothing")
	}
	t.Logf("one flipped byte in the last segment, detected with no key: %s",
		keyFieldString(t, after, "signature_note"))
}

// Record handles are their own space.
func TestARecordHandleIsNotSomeOtherFamilysHandle(t *testing.T) {
	recordTestCase(t)
	_, errObj := unwrapPairNoFatal(RecordLayout(intObj(999)))
	if errObj == nil {
		t.Fatal("an invented handle resolved")
	}
	if !strings.Contains(errObj.Message, "record_open") {
		t.Fatalf("the refusal does not say where record handles come from: %s", errObj.Message)
	}
	t.Logf("refused: %s", errObj.Message)
}

// The layout is public, and it says so.
func TestTheLayoutIsPublicAndSegmentsStayInsideTheirSpan(t *testing.T) {
	recordTestCase(t)
	source, dest, _ := recordFixture(t)
	restricted := mustHash(t, RecordClassifyRange(intObj(30), intObj(150), stringObj("restricted")))
	mustHash(t, RecordSeal(stringObj(source), stringObj(dest),
		recordArray(restricted), recordSealOpts(nil)))

	opened := mustHash(t, RecordOpen(stringObj(dest)))
	handle := mustHashValue(t, opened, "handle")
	defer RecordClose(handle)

	layout := mustHash(t, RecordLayout(handle))
	if !mustHashBoolValue(t, layout, "boundaries_are_public") {
		t.Fatal("the layout does not state that boundaries are public")
	}
	spans, _ := mustHashValue(t, layout, "spans").(*object.Array)
	segments, _ := mustHashValue(t, layout, "segments").(*object.Array)
	for _, element := range segments.Elements {
		segment, _ := element.(*object.Hash)
		offset := mustHashValue(t, segment, "offset").(*object.Integer).Value
		length := mustHashValue(t, segment, "length").(*object.Integer).Value
		class := keyFieldString(t, segment, "class")
		var inside bool
		for _, spanElement := range spans.Elements {
			span, _ := spanElement.(*object.Hash)
			spanOffset := mustHashValue(t, span, "offset").(*object.Integer).Value
			spanLength := mustHashValue(t, span, "length").(*object.Integer).Value
			if offset >= spanOffset && offset+length <= spanOffset+spanLength {
				if keyFieldString(t, span, "class") != class {
					t.Fatalf("segment at %d carries a class its span does not", offset)
				}
				inside = true
			}
		}
		if !inside {
			t.Fatalf("the segment at %d+%d straddles a classification boundary, so its key would open "+
				"bytes of two classifications", offset, length)
		}
	}
	t.Logf("%d segments across %d spans, none straddling a boundary",
		len(segments.Elements), len(spans.Elements))
}

// Rounding grows exactly one class, and the examiner names which.
//
// Quantising rounds a range's boundaries outward, and every byte it grows over
// stops carrying the class it had and starts carrying the range's. Whether
// that withholds those bytes or releases them depends on which of the two
// classes is the more sensitive -- and nothing in this tree orders classes, so
// nothing here can work it out. With default `restricted` and a four-byte
// `open` passage, rounding to sixteen used to hand out twelve bytes nobody
// cleared, and report them in a field documented as bytes WITHHELD.
func TestQuantisingWillNotGrowAClassNobodyNamed(t *testing.T) {
	recordTestCase(t)
	source, dest, _ := recordFixture(t)
	ranges := recordArray(mustHash(t, RecordClassifyRange(intObj(20), intObj(4), stringObj("open"))))

	// The shape of a disclosure review: everything withheld except what has
	// been read and released.
	opts := func(extra map[string]object.Object) object.Object {
		base := map[string]object.Object{
			"default": stringObj("restricted"), "segment_size": intObj(16),
			"quantum": intObj(16), "sign": boolObj(false),
		}
		for key, value := range extra {
			base[key] = value
		}
		return makeHashObject(base)
	}

	_, errObj := unwrapPairNoFatal(RecordSealQuantised(stringObj(source), stringObj(dest), ranges, opts(nil)))
	if errObj == nil {
		t.Fatal("rounding with no class named was accepted, and it grows a class silently")
	}
	if !strings.Contains(errObj.Message, "rounds_to") {
		t.Fatalf("the refusal does not name the option that fixes it: %s", errObj.Message)
	}

	// Naming a class that is not the one being widened is refused too, so the
	// option cannot be satisfied by writing down any declared label.
	_, errObj = unwrapPairNoFatal(RecordSealQuantised(stringObj(source), stringObj(dest), ranges,
		opts(map[string]object.Object{"rounds_to": stringObj("restricted")})))
	if errObj == nil {
		t.Fatal("a range whose class was not named was rounded anyway")
	}
	if !strings.Contains(errObj.Message, "would widen the range at 20+4") {
		t.Fatalf("the refusal does not say which range it would not round: %s", errObj.Message)
	}

	// Named: the widening happens, and the record records which way it went.
	sealed := mustHash(t, RecordSealQuantised(stringObj(source), stringObj(dest), ranges,
		opts(map[string]object.Object{"rounds_to": stringObj("open")})))
	if got := mustHashStringValue(t, sealed, "rounds_to"); got != "open" {
		t.Fatalf("the record says rounding grew %q, want open", got)
	}
	if extra := mustHashIntValue(t, sealed, "quantised_extra"); extra != 12 {
		t.Fatalf("12 bytes moved out of restricted and the record reports %d", extra)
	}

	// And a recipient holding no key reads the direction, not only the count.
	verified := mustHash(t, RecordVerify(stringObj(dest)))
	openTag, errObj := recordLookupClass("test", "open")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	if got := mustHashStringValue(t, verified, "rounds_to"); got != openTag.Tag {
		t.Fatalf("record_verify reports rounds_to %q, want the tag of open", got)
	}
	t.Logf("rounding grew `open` by 12 bytes, and the record says so with no key")
}
