package builtin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mutant/object"
)

// evtxFixtureRecord is one event record as libevtx lays it out: "**\0\0", the
// record's size, its identifier and its written time, then the event as BinXML,
// then the size again. The event here is the smallest fragment there is -- a
// fragment header and the end-of-stream token -- which the library parses
// cleanly into an empty event.
func evtxFixtureRecord(id uint64, statedSize uint32) []byte {
	binXML := []byte{0x0F, 0x01, 0x01, 0x00, 0x00}
	size := 24 + len(binXML) + 3 + 4
	r := make([]byte, size)
	copy(r, "**\x00\x00")
	binary.LittleEndian.PutUint32(r[4:], statedSize)
	binary.LittleEndian.PutUint64(r[8:], id)
	binary.LittleEndian.PutUint64(r[16:], uint64((int64(1600000000)+filetimeEpochDeltaSec)*10_000_000))
	copy(r[24:], binXML)
	binary.LittleEndian.PutUint32(r[size-4:], statedSize)
	return r
}

// evtxFixture writes an EVTX file of one chunk: the 4096-byte file header, then
// a 64 KiB chunk whose header declares records first..last and whose records
// start at 0x200 (libevtx: file header, chunk header, event records).
func evtxFixture(t *testing.T, first, last uint64, records ...[]byte) string {
	t.Helper()
	file := make([]byte, 4096+65536)
	copy(file, "ElfFile\x00")
	binary.LittleEndian.PutUint32(file[32:], 128)  // header size
	binary.LittleEndian.PutUint16(file[36:], 1)    // minor version
	binary.LittleEndian.PutUint16(file[38:], 3)    // major version
	binary.LittleEndian.PutUint16(file[40:], 4096) // header block size

	chunk := file[4096:]
	copy(chunk, "ElfChnk\x00")
	binary.LittleEndian.PutUint64(chunk[8:], first)
	binary.LittleEndian.PutUint64(chunk[16:], last)
	binary.LittleEndian.PutUint64(chunk[24:], first)
	binary.LittleEndian.PutUint64(chunk[32:], last)
	binary.LittleEndian.PutUint32(chunk[40:], 128)
	off := 0x200
	for _, r := range records {
		off += copy(chunk[off:], r)
	}

	path := filepath.Join(t.TempDir(), "test.evtx")
	if err := os.WriteFile(path, file, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// evtxParseWithin runs evtx_parse and fails rather than hangs.
func evtxParseWithin(t *testing.T, path string, limit time.Duration) *object.Hash {
	t.Helper()
	done := make(chan object.Object, 1)
	go func() { done <- EvtxParse(stringObj(path)) }()
	select {
	case res := <-done:
		got, errObj := unwrapPair(t, res)
		if errObj != nil {
			t.Fatalf("evtx_parse: %s", errObj.Inspect())
		}
		return got.(*object.Hash)
	case <-time.After(limit):
		t.Fatalf("evtx_parse did not return within %s", limit)
		return nil
	}
}

// TestEvtxParseReadsEveryRecordAChunkHolds: three well-formed records, three
// events, in order. The walk that bounds the library must not cost a record.
func TestEvtxParseReadsEveryRecordAChunkHolds(t *testing.T) {
	r1, r2, r3 := evtxFixtureRecord(1, 36), evtxFixtureRecord(2, 36), evtxFixtureRecord(3, 36)
	got := evtxParseWithin(t, evtxFixture(t, 1, 3, r1, r2, r3), 5*time.Second)
	if n := hInt(t, got, "count"); n != 3 {
		t.Fatalf("count = %d, want 3", n)
	}
	for i, e := range hashValueByKey(got, "records").(*object.Array).Elements {
		if id := hInt(t, e.(*object.Hash), "record_id"); id != int64(i+1) {
			t.Errorf("record %d has record_id %d, want %d", i, id, i+1)
		}
	}
}

// TestAChunkIsParsedForTheRecordsItHolds is M26-ART-006's regression test: a
// chunk declaring a hundred thousand records over one record that states a size
// of zero. The library re-read that record at the same offset for every
// declared number and returned 100,000 copies of it; at 2^64 it ran the process
// out of memory. A record whose size cannot be its size is where the walk stops.
func TestAChunkIsParsedForTheRecordsItHolds(t *testing.T) {
	got := evtxParseWithin(t, evtxFixture(t, 1, 100_000, evtxFixtureRecord(1, 0)), 5*time.Second)
	if n := hInt(t, got, "count"); n != 0 {
		t.Fatalf("count = %d, want 0: the one record states a size of zero, so it delimits nothing", n)
	}

	// The same declaration over records that are well formed parses those and
	// no more: the count is what the chunk holds, not what it claims.
	r1, r2 := evtxFixtureRecord(1, 36), evtxFixtureRecord(2, 36)
	got = evtxParseWithin(t, evtxFixture(t, 1, 1<<62, r1, r2), 5*time.Second)
	if n := hInt(t, got, "count"); n != 2 {
		t.Fatalf("count = %d, want the 2 records the chunk holds", n)
	}
}
