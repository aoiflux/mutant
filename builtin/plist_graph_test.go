package builtin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mutant/object"
)

// bplistOf assembles a bplist00 from encoded objects (a marker byte and its
// payload each), with four-byte offsets and one-byte object references, so up to
// 256 objects. The layout is Apple's CFBinaryPList: the objects, then the offset
// table, then a 32-byte trailer holding the offset size at 6, the reference
// size at 7, and the object count, top object and table offset as big-endian
// uint64s at 8, 16 and 24.
func bplistOf(top int, objects ...[]byte) []byte {
	buf := []byte("bplist00")
	offsets := make([]int, len(objects))
	for i, o := range objects {
		offsets[i] = len(buf)
		buf = append(buf, o...)
	}
	table := len(buf)
	for _, off := range offsets {
		buf = binary.BigEndian.AppendUint32(buf, uint32(off))
	}
	trailer := make([]byte, 32)
	trailer[6], trailer[7] = 4, 1
	binary.BigEndian.PutUint64(trailer[8:], uint64(len(objects)))
	binary.BigEndian.PutUint64(trailer[16:], uint64(top))
	binary.BigEndian.PutUint64(trailer[24:], uint64(table))
	return append(buf, trailer...)
}

// bpArray encodes an array of one-byte references. A count of 15 or more is
// written as 0xAF followed by an int object holding it.
func bpArray(refs ...int) []byte {
	var b []byte
	if len(refs) < 15 {
		b = []byte{0xA0 | byte(len(refs))}
	} else {
		b = []byte{0xAF, 0x12}
		b = binary.BigEndian.AppendUint32(b, uint32(len(refs)))
	}
	for _, r := range refs {
		b = append(b, byte(r))
	}
	return b
}

// bpASCII encodes an ASCII string object.
func bpASCII(s string) []byte {
	b := []byte{0x5F, 0x12}
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

func plistParseBytes(t *testing.T, data []byte) (object.Object, *object.Error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.plist")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return unwrapPair(t, PlistParse(stringObj(path)))
}

// plistParseWithin parses and fails rather than hangs.
func plistParseWithin(t *testing.T, data []byte, limit time.Duration) (object.Object, *object.Error) {
	t.Helper()
	type result struct {
		value object.Object
		err   *object.Error
	}
	done := make(chan result, 1)
	path := filepath.Join(t.TempDir(), "test.plist")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	go func() {
		res := PlistParse(stringObj(path))
		v, e := unwrapPair(t, res)
		done <- result{v, e}
	}()
	select {
	case r := <-done:
		return r.value, r.err
	case <-time.After(limit):
		t.Fatalf("plist_parse did not return within %s", limit)
		return nil, nil
	}
}

// TestABinaryPlistThatSharesContainersIsRefusedNotExpanded is M26-ART-008's
// regression test: forty arrays, each holding two references to the next, are
// 2^40 values from a couple of hundred bytes. The old parser expanded them, one
// fresh parse per reference.
func TestABinaryPlistThatSharesContainersIsRefusedNotExpanded(t *testing.T) {
	const levels = 40
	objects := make([][]byte, 0, levels+1)
	for i := 0; i < levels; i++ {
		objects = append(objects, bpArray(i+1, i+1))
	}
	objects = append(objects, []byte{0x09}) // true
	_, errObj := plistParseWithin(t, bplistOf(0, objects...), 2*time.Second)
	if errObj == nil || !strings.Contains(errObj.Inspect(), "more values than it has bytes") {
		t.Fatalf("plist_parse of a 2^%d-value plist: error = %v, want a refusal", levels, errObj)
	}
}

// TestABinaryPlistContainerThatHoldsItselfIsNamed: a container that lists itself
// is a cycle, and is named as one rather than run down to the depth cap.
func TestABinaryPlistContainerThatHoldsItselfIsNamed(t *testing.T) {
	_, errObj := plistParseBytes(t, bplistOf(0, bpArray(0)))
	if errObj == nil || !strings.Contains(errObj.Inspect(), "contains itself") {
		t.Fatalf("plist_parse of an array holding itself: error = %v, want it named", errObj)
	}
}

// TestABinaryPlistMayShareWhatItsWritersShare: every writer shares equal
// strings and numbers, so an array of a thousand references to one 4 KiB string
// is ordinary. It parses, and the string's bytes are held once rather than once
// per reference.
//
// The measurement is against the same plist with one reference instead of a
// thousand, which is what isolates the cost of a reference from the cost of
// parsing anything at all. Holding the string once costs a header and a pointer
// per reference; holding it per reference costs 4 KiB, and the allowance is an
// eighth of that -- thirteen times what sharing takes and an eighth of what
// copying takes.
func TestABinaryPlistMayShareWhatItsWritersShare(t *testing.T) {
	const references = 1000
	const allowance = references * 4096 / 8

	big := strings.Repeat("A", 4096)
	sharing := func(n int) []byte {
		refs := make([]int, n)
		for i := range refs {
			refs[i] = 1
		}
		return bplistOf(0, bpArray(refs...), bpASCII(big))
	}
	one, many := sharing(1), sharing(references)

	var value object.Object
	var errObj *object.Error
	gap := allocationGap(
		func() { _, _ = plistParseBytes(t, one) },
		func() { value, errObj = plistParseBytes(t, many) })
	if errObj != nil {
		t.Fatalf("plist_parse: %s", errObj.Inspect())
	}
	arr, ok := value.(*object.Array)
	if !ok || len(arr.Elements) != references ||
		arr.Elements[references-1].(*object.String).Value != big {
		t.Fatalf("plist_parse = %T with %d elements, want %d copies of the string",
			value, len(arr.Elements), references)
	}
	if gap > allowance {
		t.Errorf("plist_parse allocated %d bytes more for %d references to one 4096-byte "+
			"string than for one reference, over the %d-byte allowance: the bytes are "+
			"being held once per reference", gap, references, allowance)
	}
}

// TestABinaryPlistCannotDeclareObjectsItsTableDoesNotHold is M26-ART-035, found
// while making the bound above differential: a trailer declaring two objects
// over a table with room for one was accepted, which meant the twin and the
// real case were not the same refusal.
//
// The bound measured from the offset table's start to the end of the file, and
// the last thirty-two bytes of a binary plist are the trailer, not table. On
// this 45-byte fixture, with four-byte offsets and the table at byte 9, the
// table holds exactly one entry and nine objects were allowed. The eight
// phantoms took their offsets from the trailer's own bytes, and with the top
// object pointing at one, plist_parse returned an *object.String of two
// characters decoded from those trailer bytes: not a refusal and not a drop,
// but a fabricated answer about an artifact.
func TestABinaryPlistCannotDeclareObjectsItsTableDoesNotHold(t *testing.T) {
	declaring := func(top int, count uint64) (object.Object, *object.Error) {
		data := bplistOf(top, []byte{0x09})
		binary.BigEndian.PutUint64(data[len(data)-32+8:], count)
		return plistParseBytes(t, data)
	}

	// One object and one entry to hold it: the file is honest and parses.
	value, errObj := declaring(0, 1)
	if errObj != nil {
		t.Fatalf("an honest one-object plist was refused: %s", errObj.Inspect())
	}
	if _, isBool := value.(*object.Boolean); !isBool {
		t.Fatalf("plist_parse = %T, want the BOOLEAN the file holds", value)
	}

	// Everything past what the table holds is refused, whether or not the top
	// object is one of the phantoms. Two is already past it.
	for _, count := range []uint64{2, 3, 9, 10, 1 << 24} {
		if _, errObj := declaring(0, count); errObj == nil {
			t.Errorf("a plist declaring %d objects over a one-entry offset table was accepted",
				count)
		}
		if _, errObj := declaring(int(count-1), count); errObj == nil {
			t.Errorf("a plist declaring %d objects, with the top object at %d and its offset "+
				"read out of the trailer, was accepted", count, count-1)
		}
	}
}

// TestABinaryPlistIsNotSizedByItsCounts is the plist half of M26-ART-005: an
// object count and an array count, each 2^24, over a file a few dozen bytes
// long. Sized by their counts they asked for 128 MiB and 256 MiB.
//
// Each is measured against the same file declaring a far smaller number of the
// same thing, chosen so that it is refused for the reason 2^24 is -- the file
// holds one -- which makes both measurements measurements of the same refusal,
// and the difference between them the cost of the number and nothing else. Each
// subtest fails if its twin is accepted, because from that point the difference
// says nothing. See allocation_gap_test.go for why the absolute figure this
// asserted until 2026-10-06 could not survive a full run of this package.
func TestABinaryPlistIsNotSizedByItsCounts(t *testing.T) {
	t.Run("the trailer's object count", func(t *testing.T) {
		objects := func(declared uint64) []byte {
			data := bplistOf(0, []byte{0x09})
			binary.BigEndian.PutUint64(data[len(data)-32+8:], declared)
			return data
		}
		// Two is the first count past what the table holds, so it is refused
		// for the reason 2^24 is. It was accepted until M26-ART-035 was fixed,
		// which is how that defect was found: the twin was not a refusal at
		// all, and the guard below said so.
		honest, claimed := objects(2), objects(1<<24)
		var honestErr, errObj *object.Error
		requireNoAllocationGap(t, "plist_parse of a file claiming 2^24 objects",
			func() { _, honestErr = plistParseBytes(t, honest) },
			func() { _, errObj = plistParseBytes(t, claimed) })
		if honestErr == nil {
			t.Fatal("the twin declaring two objects was accepted, so the two measurements " +
				"are not of the same refusal and the difference means nothing")
		}
		if errObj == nil {
			t.Error("plist_parse accepted an object count its offset table cannot hold")
		}
	})
	t.Run("an array's count", func(t *testing.T) {
		// A long-form array count: 0xAF introduces it, 0x12 says the count is
		// four bytes, and one reference byte follows whatever it says.
		array := func(declared byte) []byte {
			return bplistOf(0, []byte{0xAF, 0x12, 0x00, 0x00, 0x00, declared, 0x01})
		}
		honest := array(0x02)
		claimed := bplistOf(0, []byte{0xAF, 0x12, 0x01, 0x00, 0x00, 0x00, 0x01})
		var honestErr, errObj *object.Error
		requireNoAllocationGap(t, "plist_parse of an array claiming 2^24 references",
			func() { _, honestErr = plistParseBytes(t, honest) },
			func() { _, errObj = plistParseBytes(t, claimed) })
		if honestErr == nil {
			t.Fatal("the twin declaring two references was accepted, so the two measurements " +
				"are not of the same refusal and the difference means nothing")
		}
		if errObj == nil {
			t.Error("plist_parse accepted an array count its references cannot fill")
		}
	})
}

// xmlPlistNest builds a plist whose root is `levels` containers nested one
// inside the next, with `leaf` written inside the innermost one. The element is
// "array" or "dict"; a dict needs a <key> before each value, which is the shape
// the parser actually walks.
//
// The leaf matters when the figure does. A container with nothing inside it
// never asks the parser for the level below, so 101 bare containers reach depth
// 100 while 101 containers around a leaf reach 101.
func xmlPlistNest(element string, levels int, leaf string) []byte {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	sb.WriteString(`<plist version="1.0">` + "\n")
	for i := 0; i < levels; i++ {
		sb.WriteString("<" + element + ">")
		if element == "dict" {
			sb.WriteString("<key>k</key>")
		}
	}
	sb.WriteString(leaf)
	for i := 0; i < levels; i++ {
		sb.WriteString("</" + element + ">")
	}
	sb.WriteString("\n</plist>\n")
	return []byte(sb.String())
}

// TestAnXMLPlistIsRefusedPastTheSameDepthAsABinaryOne is M26-ART-009.
//
// The binary parser has always refused past maxPlistDepth. The XML parser had no
// counter, and parseXMLPlistValue and parseXMLPlistArray call each other once
// per level, so nested <array> elements grew the stack until the process died --
// a stack overflow is fatal, no recover catches it, and PlistParse's own recover
// is therefore no help. The row measured 168 to 839 bytes of stack per level,
// which the default gigabyte reaches at a 9 to 45 MB file.
//
// Run under a lowered ceiling, so a regression dies at 64 MiB rather than
// taking the machine with it. It still takes the test binary with it, which is
// the loudest a fatal error can fail.
func TestAnXMLPlistIsRefusedPastTheSameDepthAsABinaryOne(t *testing.T) {
	smallStack(t)
	for _, element := range []string{"array", "dict"} {
		_, errObj := plistParseWithin(t, xmlPlistNest(element, 1000, ""), 10*time.Second)
		if errObj == nil || !strings.Contains(errObj.Inspect(), "nested more than 100 levels deep") {
			t.Errorf("plist_parse of 1000 nested <%s>: error = %v, want the depth refusal",
				element, errObj)
		}
	}

	// The wrapper is optional, and a plist without one reaches the value parser
	// by a different line. The count has to start there too.
	bare := []byte(`<?xml version="1.0"?>` + strings.Repeat("<array>", 1000) +
		strings.Repeat("</array>", 1000))
	_, errObj := plistParseWithin(t, bare, 10*time.Second)
	if errObj == nil || !strings.Contains(errObj.Inspect(), "nested more than 100 levels deep") {
		t.Errorf("plist_parse of 1000 nested <array> with no <plist> wrapper: error = %v, "+
			"want the depth refusal", errObj)
	}
}

// TestTheXMLAndBinaryPlistDepthBoundsAreTheSameOne keeps the bound from becoming
// the defect, and checks the agreement the shared constant is there to express.
//
// Both parsers count the root as level zero, walk the leaf as a level of its
// own, and refuse past maxPlistDepth. So both accept 100 containers around a
// value and refuse 101 -- the same figure on the same shape, which is a stronger
// statement than the same figure on two different shapes. The numbers are
// written out rather than derived from the constant, so that moving the constant
// is a decision someone makes here as well.
func TestTheXMLAndBinaryPlistDepthBoundsAreTheSameOne(t *testing.T) {
	if maxPlistDepth != 100 {
		t.Fatalf("these figures are written for a bound of 100, not %d", maxPlistDepth)
	}

	for _, element := range []string{"array", "dict"} {
		within := xmlPlistNest(element, 100, "<true/>")
		if _, errObj := plistParseWithin(t, within, 10*time.Second); errObj != nil {
			t.Errorf("100 nested <%s> around a value is within the bound: error = %v",
				element, errObj)
		}
		past := xmlPlistNest(element, 101, "<true/>")
		if _, errObj := plistParseWithin(t, past, 10*time.Second); errObj == nil {
			t.Errorf("101 nested <%s> around a value is past the bound, but it was accepted",
				element)
		}
	}

	// The binary path, as a chain of arrays each holding the next and a boolean
	// at the end, so the two are compared on one shape and not on one wording.
	chain := func(levels int) []byte {
		objects := make([][]byte, 0, levels+1)
		for i := 0; i < levels; i++ {
			objects = append(objects, bpArray(i+1))
		}
		return bplistOf(0, append(objects, []byte{0x09})...)
	}
	if _, errObj := plistParseWithin(t, chain(100), 10*time.Second); errObj != nil {
		t.Errorf("a binary plist of 100 nested arrays around a value is within the bound: "+
			"error = %v", errObj)
	}
	if _, errObj := plistParseWithin(t, chain(101), 10*time.Second); errObj == nil {
		t.Errorf("a binary plist of 101 nested arrays around a value is past the bound, " +
			"but it was accepted")
	}
}

// TestATruncatedXMLPlistKeepsWhatItHeld pins the leniency the depth refusal had
// to be threaded past.
//
// Both container parsers answer a child's error with the part of the tree they
// already hold and no error of their own, which is how a plist cut short still
// parses. A depth refusal returned that way would make the parse succeed and
// hand back only the tree above the bound -- a silent truncation of the file's
// contents -- so it travels as a sentinel instead, and only the sentinel is
// propagated. This is the test that notices if that distinction is lost: it
// fails if the refusal starts swallowing the ordinary case with it.
func TestATruncatedXMLPlistKeepsWhatItHeld(t *testing.T) {
	cut := []byte(`<?xml version="1.0"?><plist version="1.0"><dict>` +
		`<key>kept</key><string>yes</string>` +
		`<key>dangling</key><array><string>also kept</string>`)

	value, errObj := plistParseWithin(t, cut, 10*time.Second)
	if errObj != nil {
		t.Fatalf("a truncated plist is read as far as it goes: error = %v", errObj)
	}
	hash, ok := value.(*object.Hash)
	if !ok {
		t.Fatalf("got %T, want the dict that was read before the file ended", value)
	}
	if !strings.Contains(hash.Inspect(), "kept") {
		t.Errorf("the pairs read before the end are kept, got %s", hash.Inspect())
	}
}
