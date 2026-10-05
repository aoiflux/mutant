package builtin

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"mutant/object"
)

// These hives are built cell by cell after Suhanov's "Windows registry file
// format specification": the minor version at 0x18 of the base block; a big data
// record as "db", a segment count and the offset of a list of segment offsets,
// each segment holding at most 16344 bytes; an index root as "ri", a count and
// the offsets of the lists it names. The literals are the format's, written out
// here so the parser is held to the specification and not to its own constants.

// writeHive stores a built hive and opens it the way hive_open does.
func writeHive(t *testing.T, b *hiveBuilder, rootRel uint32) (*regfHive, string) {
	t.Helper()
	binary.LittleEndian.PutUint32(b.buf[0x24:], rootRel)
	path := filepath.Join(t.TempDir(), "test.hve")
	if err := os.WriteFile(path, b.buf, 0o644); err != nil {
		t.Fatalf("write hive: %v", err)
	}
	h, err := openRegfHive(path)
	if err != nil {
		t.Fatalf("open hive: %v", err)
	}
	return h, path
}

// regfBinaryVK allocates a REG_BINARY vk record named name whose data offset
// points at dataRel and whose recorded size is size.
func regfBinaryVK(b *hiveBuilder, name string, size, dataRel uint32) uint32 {
	vk := make([]byte, 0x14+len(name))
	copy(vk, "vk")
	binary.LittleEndian.PutUint16(vk[0x02:], uint16(len(name)))
	binary.LittleEndian.PutUint32(vk[0x04:], size)
	binary.LittleEndian.PutUint32(vk[0x08:], dataRel)
	binary.LittleEndian.PutUint32(vk[0x0C:], 3) // REG_BINARY
	binary.LittleEndian.PutUint16(vk[0x10:], 1) // ASCII name
	copy(vk[0x14:], name)
	return b.alloc(vk)
}

// bigDataRecord stores payload as a big data record: segments of at most 16344
// bytes, a list of their offsets, and the "db" record naming the list.
func bigDataRecord(b *hiveBuilder, payload []byte) uint32 {
	var segs []uint32
	for off := 0; off < len(payload); off += 16344 {
		segs = append(segs, b.alloc(payload[off:min(off+16344, len(payload))]))
	}
	list := make([]byte, 4*len(segs))
	for i, s := range segs {
		binary.LittleEndian.PutUint32(list[4*i:], s)
	}
	listRel := b.alloc(list)
	db := make([]byte, 8)
	copy(db, "db")
	binary.LittleEndian.PutUint16(db[2:], uint16(len(segs)))
	binary.LittleEndian.PutUint32(db[4:], listRel)
	return b.alloc(db)
}

// rootWithValues allocates a value list and the root key holding it.
func rootWithValues(b *hiveBuilder, valueCount uint32, vks ...uint32) uint32 {
	list := make([]byte, 4*len(vks))
	for i, vk := range vks {
		binary.LittleEndian.PutUint32(list[4*i:], vk)
	}
	return b.alloc(makeNK("ROOT", 0, 0, 0xFFFFFFFF, valueCount, b.alloc(list)))
}

func patterned(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i*7 + i/251)
	}
	return p
}

// hiveGetValueBytes reads one value's bytes through hive_open and
// hive_get_value, the way a script does.
func hiveGetValueBytes(t *testing.T, path, name string) []byte {
	t.Helper()
	opened, errObj := unwrapPair(t, HiveOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("hive_open: %s", errObj.Inspect())
	}
	handle := hashValueByKey(opened.(*object.Hash), "handle")
	defer HiveClose(handle)
	got, errObj := unwrapPair(t, HiveGetValue(handle, stringObj(""), stringObj(name)))
	if errObj != nil {
		t.Fatalf("hive_get_value: %s", errObj.Inspect())
	}
	data, ok := hashValueByKey(got.(*object.Hash), "data_bytes").(*object.Bytes)
	if !ok {
		t.Fatalf("hive_get_value(%q) carries no data_bytes: %s", name, got.Inspect())
	}
	return data.Value
}

// TestAValueOverOneSegmentIsReadThroughItsBigDataRecord is M26-ART-010's
// regression test: 20000 bytes on a version 1.5 hive, stored the way Windows
// stores it, come back as 20000 bytes and not as the 8-byte record indexing
// them.
func TestAValueOverOneSegmentIsReadThroughItsBigDataRecord(t *testing.T) {
	b := newHiveBuilder(0)
	binary.LittleEndian.PutUint32(b.buf[0x18:], 5)
	payload := patterned(20000)
	root := rootWithValues(b, 1, regfBinaryVK(b, "Blob", uint32(len(payload)), bigDataRecord(b, payload)))
	_, path := writeHive(t, b, root)

	if got := hiveGetValueBytes(t, path, "Blob"); !bytes.Equal(got, payload) {
		t.Fatalf("hive_get_value returned %d bytes, want the %d-byte value (first bytes % x)", len(got), len(payload), got[:min(len(got), 12)])
	}
}

// TestAnOlderHiveKeepsALongValueInOneCell holds the version gate: before 1.4 a
// hive has no big data records, so a long value is one cell even when its first
// two bytes spell "db".
func TestAnOlderHiveKeepsALongValueInOneCell(t *testing.T) {
	b := newHiveBuilder(0)
	binary.LittleEndian.PutUint32(b.buf[0x18:], 3)
	payload := patterned(20000)
	copy(payload, "db\x01\x00")
	root := rootWithValues(b, 1, regfBinaryVK(b, "Blob", uint32(len(payload)), b.alloc(payload)))
	_, path := writeHive(t, b, root)

	if got := hiveGetValueBytes(t, path, "Blob"); !bytes.Equal(got, payload) {
		t.Fatalf("a version 1.3 hive's 20000-byte value came back as %d bytes", len(got))
	}
}

// TestAShortValueThatBeginsWithDbIsData holds the size gate on both readers: a
// big data record holds a value of more than one segment, so eight bytes that
// happen to spell "db", a count and an offset are eight bytes of data.
// shimcache_parse reads through rawValueBytes, which used to take any cell
// beginning "db" for a big data record.
func TestAShortValueThatBeginsWithDbIsData(t *testing.T) {
	b := newHiveBuilder(0)
	binary.LittleEndian.PutUint32(b.buf[0x18:], 5)
	payload := []byte{'d', 'b', 0x01, 0x00, 0x20, 0x00, 0x00, 0x00}
	vk := regfBinaryVK(b, "Short", uint32(len(payload)), b.alloc(payload))
	root := rootWithValues(b, 1, vk)
	h, path := writeHive(t, b, root)

	if got := hiveGetValueBytes(t, path, "Short"); !bytes.Equal(got, payload) {
		t.Errorf("hive_get_value = % x, want % x", got, payload)
	}
	parsed, err := h.parseVK(vk)
	if err != nil {
		t.Fatal(err)
	}
	if got := h.rawValueBytes(parsed); !bytes.Equal(got, payload) {
		t.Errorf("rawValueBytes = % x, want % x", got, payload)
	}
}

// listKeysWithin runs hive_list_keys on the root and fails rather than hangs.
func listKeysWithin(t *testing.T, path string, limit time.Duration) []string {
	t.Helper()
	opened, errObj := unwrapPair(t, HiveOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("hive_open: %s", errObj.Inspect())
	}
	handle := hashValueByKey(opened.(*object.Hash), "handle")
	defer HiveClose(handle)

	done := make(chan object.Object, 1)
	go func() { done <- HiveListKeys(handle) }()
	select {
	case res := <-done:
		got, errObj := unwrapPair(t, res)
		if errObj != nil {
			t.Fatalf("hive_list_keys: %s", errObj.Inspect())
		}
		var names []string
		for _, e := range got.(*object.Array).Elements {
			names = append(names, e.(*object.String).Value)
		}
		return names
	case <-time.After(limit):
		t.Fatalf("hive_list_keys did not return within %s", limit)
		return nil
	}
}

// TestAnIndexRootIsReadOnceHoweverOftenItIsListed is M26-ART-004's regression
// test. Twenty index roots, each naming the next one twice, end at a leaf list
// holding one key: the old walk returned 2^20 copies of it. An index root that
// names itself twice cost 2^33 calls.
func TestAnIndexRootIsReadOnceHoweverOftenItIsListed(t *testing.T) {
	t.Run("a chain of twenty", func(t *testing.T) {
		b := newHiveBuilder(0)
		child := b.alloc(makeNK("Child", 0, 0, 0xFFFFFFFF, 0, 0xFFFFFFFF))
		lf := make([]byte, 4+8)
		copy(lf, "lf")
		binary.LittleEndian.PutUint16(lf[2:], 1)
		binary.LittleEndian.PutUint32(lf[4:], child)
		next := b.alloc(lf)
		for i := 0; i < 20; i++ {
			ri := make([]byte, 4+8)
			copy(ri, "ri")
			binary.LittleEndian.PutUint16(ri[2:], 2)
			binary.LittleEndian.PutUint32(ri[4:], next)
			binary.LittleEndian.PutUint32(ri[8:], next)
			next = b.alloc(ri)
		}
		_, path := writeHive(t, b, b.alloc(makeNK("ROOT", 0, 1, next, 0, 0xFFFFFFFF)))
		if got := listKeysWithin(t, path, 5*time.Second); len(got) != 1 || got[0] != "Child" {
			t.Fatalf("hive_list_keys returned %d names, want exactly [Child]", len(got))
		}
	})

	t.Run("an index root naming itself", func(t *testing.T) {
		b := newHiveBuilder(0)
		self := b.cursor // the cell's offset once allocated
		ri := make([]byte, 4+8)
		copy(ri, "ri")
		binary.LittleEndian.PutUint16(ri[2:], 2)
		binary.LittleEndian.PutUint32(ri[4:], self)
		binary.LittleEndian.PutUint32(ri[8:], self)
		if got := b.alloc(ri); got != self {
			t.Fatalf("builder put the cell at %#x, not %#x", got, self)
		}
		_, path := writeHive(t, b, b.alloc(makeNK("ROOT", 0, 1, self, 0, 0xFFFFFFFF)))
		if got := listKeysWithin(t, path, 5*time.Second); len(got) != 0 {
			t.Fatalf("hive_list_keys returned %v, want no keys", got)
		}
	})
}

// allocatedBy reports how many bytes fn allocated.
func allocatedBy(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestAHiveIsNotSizedByTheCountsItRecords is the hive half of M26-ART-005. A key
// whose value count is 2^24 over a one-entry list, and a value whose recorded
// size is 256 MiB over one short segment, are read by what the cells hold. Sized
// by their counts they asked for 128 MiB and 256 MiB.
func TestAHiveIsNotSizedByTheCountsItRecords(t *testing.T) {
	b := newHiveBuilder(0)
	binary.LittleEndian.PutUint32(b.buf[0x18:], 5)
	small := patterned(100)
	vk := regfBinaryVK(b, "Huge", 1<<28, bigDataRecord(b, small))
	root := rootWithValues(b, 1<<24, vk)
	h, _ := writeHive(t, b, root)

	nk, err := h.parseNK(h.rootOffset)
	if err != nil {
		t.Fatal(err)
	}
	var values []*vkValue
	if grew := allocatedBy(func() { values = h.values(nk) }); grew > 1<<20 {
		t.Errorf("values() allocated %d bytes for a one-entry list claiming 2^24 values", grew)
	}
	if len(values) != 1 {
		t.Fatalf("values() = %d values, want 1", len(values))
	}
	var raw []byte
	if grew := allocatedBy(func() { raw = h.rawValueBytes(values[0]) }); grew > 1<<20 {
		t.Errorf("rawValueBytes allocated %d bytes for a value whose one segment is %d bytes", grew, len(small))
	}
	if !bytes.Equal(raw, small) {
		t.Errorf("rawValueBytes = %d bytes, want the %d the segment holds", len(raw), len(small))
	}
}
