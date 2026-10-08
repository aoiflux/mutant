package builtin

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/aoiflux/libntfs"

	"mutant/object"
)

// mftPutNonResidentData writes an unnamed non-resident $DATA attribute: the
// 16-byte common header, then the starting and last VCN, the data run offset,
// the compression unit, four reserved bytes, and the allocated, real and
// initialised sizes, then one run of two clusters at LCN 16 (NTFS attribute
// record header, non-resident form).
func mftPutNonResidentData(rec []byte, off int, realSize, allocated uint64) int {
	const length = 0x48
	binary.LittleEndian.PutUint32(rec[off:], 0x80)
	binary.LittleEndian.PutUint32(rec[off+0x04:], length)
	rec[off+0x08] = 1                                   // non-resident
	binary.LittleEndian.PutUint64(rec[off+0x18:], 1)    // last VCN: two clusters
	binary.LittleEndian.PutUint16(rec[off+0x20:], 0x40) // data runs at 0x40
	binary.LittleEndian.PutUint64(rec[off+0x28:], allocated)
	binary.LittleEndian.PutUint64(rec[off+0x30:], realSize)
	binary.LittleEndian.PutUint64(rec[off+0x38:], realSize)
	copy(rec[off+0x40:], []byte{0x11, 0x02, 0x10, 0x00}) // two clusters at LCN 16
	return off + length
}

// deletedRecordWithData is a deleted FILE record whose $FILE_NAME says fnSize
// and whose default $DATA stream says otherwise: resident and holding resident
// bytes, or non-resident with dataSize bytes in allocated.
func deletedRecordWithData(recordNum uint32, name string, fnSize uint64, resident []byte, dataSize, allocated uint64) []byte {
	rec := make([]byte, 1024)
	copy(rec[0:4], "FILE")
	binary.LittleEndian.PutUint16(rec[0x04:], 0x30)
	binary.LittleEndian.PutUint16(rec[0x06:], 3)
	binary.LittleEndian.PutUint16(rec[0x10:], 1)
	binary.LittleEndian.PutUint16(rec[0x12:], 1)
	binary.LittleEndian.PutUint16(rec[0x14:], 0x38)
	binary.LittleEndian.PutUint32(rec[0x1C:], 1024)
	binary.LittleEndian.PutUint32(rec[0x2C:], recordNum)

	ft := mftNTFSTime(1600000000)
	off := 0x38
	off = mftPutResidentAttr(rec, off, 0x10, mftSIValue(ft))
	off = mftPutResidentAttr(rec, off, 0x30, mftFNValue(5, name, fnSize, ft, false))
	if resident != nil {
		off = mftPutResidentAttr(rec, off, 0x80, resident)
	} else {
		off = mftPutNonResidentData(rec, off, dataSize, allocated)
	}
	binary.LittleEndian.PutUint32(rec[off:], 0xFFFFFFFF)
	off += 8
	binary.LittleEndian.PutUint32(rec[0x18:], uint32(off))

	// Fixups last, because a resident value can cross a sector's end: the last
	// two bytes of each sector move into the update sequence array and the
	// update sequence number takes their place.
	const usn = 1
	binary.LittleEndian.PutUint16(rec[0x30:], usn)
	for sector := 0; sector < 2; sector++ {
		tail := (sector+1)*512 - 2
		copy(rec[0x32+2*sector:], rec[tail:tail+2])
		binary.LittleEndian.PutUint16(rec[tail:], usn)
	}
	return rec
}

// TestAFilesSizeIsItsDataStreamsAndNotItsFileNames is M26-FS2-002's regression
// test. NTFS updates the sizes $FILE_NAME carries lazily; zero, as here, is
// common. Record 0 holds 5000 bytes in a non-resident stream, record 1 holds 300
// resident bytes under a $FILE_NAME saying 100. fs_deleted, mft_parse and the
// entry ntfs_deleted builds all report the stream's size, and a recovery of
// record 0 is cut to it rather than padded out to its two clusters.
func TestAFilesSizeIsItsDataStreamsAndNotItsFileNames(t *testing.T) {
	resident := make([]byte, 300)
	for i := range resident {
		resident[i] = byte('a' + i%26)
	}
	mft := append(deletedRecordWithData(0, "report.docx", 0, nil, 5000, 8192),
		deletedRecordWithData(1, "notes.txt", 100, resident, 0, 0)...)
	path := filepath.Join(t.TempDir(), "$MFT")
	if err := os.WriteFile(path, mft, 0o644); err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"report.docx": 5000, "notes.txt": 300}

	deleted, errObj := unwrapPair(t, FsDeleted(stringObj(path)))
	if errObj != nil {
		t.Fatalf("fs_deleted: %s", errObj.Inspect())
	}
	entries := hashValueByKey(deleted.(*object.Hash), "entries").(*object.Array).Elements
	if len(entries) != len(want) {
		t.Fatalf("fs_deleted found %d entries, want %d: a record did not parse", len(entries), len(want))
	}
	for _, e := range entries {
		h := e.(*object.Hash)
		if name, size := hStr(t, h, "name"), hInt(t, h, "size"); size != want[name] {
			t.Errorf("fs_deleted %s: size = %d, want %d", name, size, want[name])
		}
	}

	parsed, errObj := unwrapPair(t, MftParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("mft_parse: %s", errObj.Inspect())
	}
	entries = hashValueByKey(parsed.(*object.Hash), "entries").(*object.Array).Elements
	if len(entries) != len(want) {
		t.Fatalf("mft_parse found %d entries, want %d", len(entries), len(want))
	}
	for _, e := range entries {
		h := e.(*object.Hash)
		if name, size := hStr(t, h, "name"), hInt(t, h, "size"); size != want[name] {
			t.Errorf("mft_parse %s: size = %d, want %d", name, size, want[name])
		}
		if hStr(t, h, "name") == "report.docx" && hInt(t, h, "allocated_size") != 8192 {
			t.Errorf("mft_parse report.docx: allocated_size = %d, want the stream's 8192", hInt(t, h, "allocated_size"))
		}
	}

	e, err := libntfs.ParseMFTRecord(mft[:1024], 0, 1024)
	if err != nil {
		t.Fatal(err)
	}
	entry := ntfsDeletedEntry(mftRowFromEntry(e, 0), `\report.docx`, fsDeletedContent{
		State: fsDeletedContentPreserved,
		Runs:  []fsDeletedRun{{FileOffset: 0, Offset: 0, Length: 8192}},
	})
	if entry.Size != 5000 {
		t.Fatalf("ntfs_deleted entry size = %d, want the stream's 5000", entry.Size)
	}
	recovery, err := recoveryFromRuns(bytes.NewReader(make([]byte, 8192)), entry, entry.Runs)
	if err != nil {
		t.Fatal(err)
	}
	if recovery.Length != 5000 {
		t.Errorf("a recovery of the 5000-byte file is %d bytes long, want it cut to the stream's size", recovery.Length)
	}
}

// TestAnAlternateStreamIsNotTheFilesSize: a record with only a named $DATA
// stream has no default stream to take a size from, and keeps $FILE_NAME's
// rather than reporting the alternate stream's length as the file's.
func TestAnAlternateStreamIsNotTheFilesSize(t *testing.T) {
	rec := deletedRecordWithData(0, "x.txt", 42, nil, 5000, 8192)
	// Name the $DATA attribute "ads": name length 3 at offset 0x48, past the
	// runs, which the attribute's length is widened to cover.
	at := 0x38
	for binary.LittleEndian.Uint32(rec[at:]) != 0x80 {
		at += int(binary.LittleEndian.Uint32(rec[at+4:]))
	}
	binary.LittleEndian.PutUint32(rec[at+0x04:], 0x50)
	rec[at+0x09] = 3
	binary.LittleEndian.PutUint16(rec[at+0x0A:], 0x48)
	copy(rec[at+0x48:], []byte{'a', 0, 'd', 0, 's', 0})
	binary.LittleEndian.PutUint32(rec[at+0x50:], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(rec[0x18:], uint32(at+0x58))

	e, err := libntfs.ParseMFTRecord(rec, 0, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if got := mftRowFromEntry(e, 0).size; got != 42 {
		t.Fatalf("size = %d, want $FILE_NAME's 42: the only $DATA stream is the alternate \"ads\"", got)
	}
}
