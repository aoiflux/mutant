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
// strings and numbers, so an array of two hundred references to one 4 KiB
// string is ordinary. It parses, and the string's bytes are held once rather
// than once per reference.
func TestABinaryPlistMayShareWhatItsWritersShare(t *testing.T) {
	big := strings.Repeat("A", 4096)
	refs := make([]int, 200)
	for i := range refs {
		refs[i] = 1
	}
	data := bplistOf(0, bpArray(refs...), bpASCII(big))

	var value object.Object
	var errObj *object.Error
	grew := allocatedBy(func() { value, errObj = plistParseBytes(t, data) })
	if errObj != nil {
		t.Fatalf("plist_parse: %s", errObj.Inspect())
	}
	arr, ok := value.(*object.Array)
	if !ok || len(arr.Elements) != 200 || arr.Elements[199].(*object.String).Value != big {
		t.Fatalf("plist_parse = %T with %d elements, want 200 copies of the string", value, len(arr.Elements))
	}
	if grew > 200*4096/2 {
		t.Errorf("plist_parse allocated %d bytes for 200 references to one 4096-byte string", grew)
	}
}

// TestABinaryPlistIsNotSizedByItsCounts is the plist half of M26-ART-005: an
// object count and an array count, each 2^24, over a file a few dozen bytes
// long. Sized by their counts they asked for 128 MiB and 256 MiB.
func TestABinaryPlistIsNotSizedByItsCounts(t *testing.T) {
	t.Run("the trailer's object count", func(t *testing.T) {
		data := bplistOf(0, []byte{0x09})
		binary.BigEndian.PutUint64(data[len(data)-32+8:], 1<<24)
		var errObj *object.Error
		if grew := allocatedBy(func() { _, errObj = plistParseBytes(t, data) }); grew > 1<<20 {
			t.Errorf("plist_parse allocated %d bytes for a %d-byte file", grew, len(data))
		}
		if errObj == nil {
			t.Error("plist_parse accepted an object count its offset table cannot hold")
		}
	})
	t.Run("an array's count", func(t *testing.T) {
		data := bplistOf(0, []byte{0xAF, 0x12, 0x01, 0x00, 0x00, 0x00, 0x01})
		var errObj *object.Error
		if grew := allocatedBy(func() { _, errObj = plistParseBytes(t, data) }); grew > 1<<20 {
			t.Errorf("plist_parse allocated %d bytes for a %d-byte file", grew, len(data))
		}
		if errObj == nil {
			t.Error("plist_parse accepted an array count its references cannot fill")
		}
	})
}
