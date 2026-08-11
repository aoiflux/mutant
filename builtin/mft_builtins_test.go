package builtin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"mutant/object"
)

// TestMFTTimeFieldsPreservesSubSecond verifies mft_parse/fs_deleted retain the
// NTFS 100 ns sub-second component — the basis for the sub-second timestomping
// tell (whole-second values across a file's SI times are suspicious).
func TestMFTTimeFieldsPreservesSubSecond(t *testing.T) {
	// 0.1234567 s = 1234567 intervals of 100 ns -> 123456700 ns.
	unix, ns, iso := mftTimeFields(time.Unix(1500000000, 123456700).UTC())
	if unix != 1500000000 {
		t.Fatalf("unix = %d, want 1500000000", unix)
	}
	if ns != 123456700 {
		t.Fatalf("ns = %d, want 123456700 (lost sub-second precision)", ns)
	}
	if !strings.Contains(iso, ".1234567") {
		t.Fatalf("iso = %q, want a sub-second fraction", iso)
	}

	// A whole-second time reports a zero fraction and no fractional part in iso.
	unix0, ns0, iso0 := mftTimeFields(time.Unix(1500000000, 0).UTC())
	if unix0 != 1500000000 || ns0 != 0 {
		t.Fatalf("whole-second: unix=%d ns=%d, want 1500000000/0", unix0, ns0)
	}
	if strings.Contains(iso0, ".") {
		t.Fatalf("whole-second iso = %q, want no fractional part", iso0)
	}
}

// --- minimal $MFT record builder (crafts valid FILE records the libntfs
// ParseMFTRecord path can consume: header + fixup + $STANDARD_INFORMATION +
// $FILE_NAME + end marker). ---

func mftNTFSTime(unix int64) uint64 {
	return uint64((unix + filetimeEpochDeltaSec) * 10_000_000)
}

func mftPutResidentAttr(rec []byte, off int, attrType uint32, value []byte) int {
	const valOff = 0x18
	length := valOff + len(value)
	if length%8 != 0 {
		length += 8 - length%8
	}
	binary.LittleEndian.PutUint32(rec[off:], attrType)
	binary.LittleEndian.PutUint32(rec[off+0x04:], uint32(length))
	// resident: non-resident flag 0, name length 0
	binary.LittleEndian.PutUint32(rec[off+0x10:], uint32(len(value))) // value length
	binary.LittleEndian.PutUint16(rec[off+0x14:], valOff)             // value offset
	copy(rec[off+valOff:], value)
	return off + length
}

func mftSIValue(ntfsTime uint64) []byte {
	v := make([]byte, 48)
	binary.LittleEndian.PutUint64(v[0:], ntfsTime)  // create
	binary.LittleEndian.PutUint64(v[8:], ntfsTime)  // modify
	binary.LittleEndian.PutUint64(v[16:], ntfsTime) // mft change
	binary.LittleEndian.PutUint64(v[24:], ntfsTime) // access
	binary.LittleEndian.PutUint32(v[32:], 0x20)     // FileAttributes = ARCHIVE
	return v
}

func mftFNValue(parentRef uint64, name string, realSize, ntfsTime uint64, isDir bool) []byte {
	nameU16 := utf16.Encode([]rune(name))
	v := make([]byte, 0x42+len(nameU16)*2)
	binary.LittleEndian.PutUint64(v[0x00:], parentRef) // low 6 bytes = parent record
	binary.LittleEndian.PutUint64(v[0x08:], ntfsTime)  // create
	binary.LittleEndian.PutUint64(v[0x10:], ntfsTime)  // modify
	binary.LittleEndian.PutUint64(v[0x18:], ntfsTime)  // mft change
	binary.LittleEndian.PutUint64(v[0x20:], ntfsTime)  // access
	binary.LittleEndian.PutUint64(v[0x28:], realSize)  // allocated
	binary.LittleEndian.PutUint64(v[0x30:], realSize)  // real
	attr := uint64(0x20)
	if isDir {
		attr = 0x10000000
	}
	binary.LittleEndian.PutUint64(v[0x38:], attr)
	v[0x40] = byte(len(nameU16)) // name length in chars
	v[0x41] = 0x01               // namespace Win32
	for i, c := range nameU16 {
		binary.LittleEndian.PutUint16(v[0x42+i*2:], c)
	}
	return v
}

func buildMFTRecord(recordNum uint32, seq uint16, isDir bool, parentRef uint64, name string, realSize, ntfsTime uint64) []byte {
	return buildMFTRecordSized(1024, recordNum, seq, isDir, parentRef, name, realSize, ntfsTime)
}

// buildMFTRecordSized crafts one MFT record of the given allocated size. NTFS
// permits sizes other than the 1024-byte default, and the record header is the
// only place that size is recorded in an extracted $MFT.
func buildMFTRecordSized(recordSize int, recordNum uint32, seq uint16, isDir bool, parentRef uint64, name string, realSize, ntfsTime uint64) []byte {
	rec := make([]byte, recordSize)
	copy(rec[0:4], "FILE")
	const usaOff = 0x30
	usaSize := recordSize/512 + 1 // USN + one fixup per sector
	binary.LittleEndian.PutUint16(rec[0x04:], usaOff)
	binary.LittleEndian.PutUint16(rec[0x06:], uint16(usaSize))
	binary.LittleEndian.PutUint16(rec[0x10:], seq)
	binary.LittleEndian.PutUint16(rec[0x12:], 1) // hard link count

	// Attributes must start past the update sequence array, 8-byte aligned.
	attrOff := usaOff + 2*usaSize
	if attrOff%8 != 0 {
		attrOff += 8 - attrOff%8
	}
	binary.LittleEndian.PutUint16(rec[0x14:], uint16(attrOff))
	flags := uint16(0x01)
	if isDir {
		flags |= 0x02
	}
	binary.LittleEndian.PutUint16(rec[0x16:], flags)
	binary.LittleEndian.PutUint32(rec[0x1C:], uint32(recordSize)) // allocated size
	binary.LittleEndian.PutUint32(rec[0x2C:], recordNum)

	// Update sequence array: USA[0] is the USN, the rest are the pre-fixup
	// bytes of each sector tail. Attributes live well before the first sector
	// end, so stamping the USN there doesn't touch them.
	const usn = 0x0001
	binary.LittleEndian.PutUint16(rec[usaOff:], usn)
	for sector := 0; sector < usaSize-1; sector++ {
		binary.LittleEndian.PutUint16(rec[usaOff+2+sector*2:], 0)
		binary.LittleEndian.PutUint16(rec[(sector+1)*512-2:], usn)
	}

	off := attrOff
	off = mftPutResidentAttr(rec, off, 0x10, mftSIValue(ntfsTime))
	off = mftPutResidentAttr(rec, off, 0x30, mftFNValue(parentRef, name, realSize, ntfsTime, isDir))
	binary.LittleEndian.PutUint32(rec[off:], 0xFFFFFFFF) // end marker
	off += 4
	if off%8 != 0 {
		off += 8 - off%8
	}
	binary.LittleEndian.PutUint32(rec[0x18:], uint32(off)) // used size
	return rec
}

func mftEntryByName(t *testing.T, arr *object.Array, name string) *object.Hash {
	t.Helper()
	for _, e := range arr.Elements {
		h := e.(*object.Hash)
		if hStr(t, h, "name") == name {
			return h
		}
	}
	t.Fatalf("no MFT entry named %q", name)
	return nil
}

func TestMftParseStandalone(t *testing.T) {
	const wantUnix = int64(1500000000)
	ft := mftNTFSTime(wantUnix)

	// Record 0: directory "Windows" under root (5). Record 1: file
	// "notepad.exe" under record 0.
	mft := make([]byte, 2*1024)
	copy(mft[0:], buildMFTRecord(0, 1, true, 5, "Windows", 0, ft))
	copy(mft[1024:], buildMFTRecord(1, 1, false, 0, "notepad.exe", 12345, ft))

	dir := t.TempDir()
	path := filepath.Join(dir, "$MFT")
	if err := os.WriteFile(path, mft, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	payload, errObj := unwrapPair(t, MftParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("mft_parse error: %s", errObj.Inspect())
	}
	h := payload.(*object.Hash)
	if got := hStr(t, h, "source_type"); got != "mft" {
		t.Errorf("source_type = %q, want mft", got)
	}
	if got := hInt(t, h, "record_size"); got != 1024 {
		t.Errorf("record_size = %d, want 1024", got)
	}
	if got := hInt(t, h, "count"); got != 2 {
		t.Fatalf("count = %d, want 2", got)
	}
	entries := hashValueByKey(h, "entries").(*object.Array)

	winDir := mftEntryByName(t, entries, "Windows")
	if !hBoolAt(t, winDir, "is_directory") {
		t.Error("Windows should be a directory")
	}
	if got := hStr(t, winDir, "path"); got != `\Windows` {
		t.Errorf("Windows path = %q, want \\Windows", got)
	}
	if got := hInt(t, winDir, "parent_record"); got != 5 {
		t.Errorf("Windows parent_record = %d, want 5", got)
	}

	np := mftEntryByName(t, entries, "notepad.exe")
	if hBoolAt(t, np, "is_directory") {
		t.Error("notepad.exe should not be a directory")
	}
	if !hBoolAt(t, np, "in_use") {
		t.Error("notepad.exe should be in use")
	}
	if got := hStr(t, np, "path"); got != `\Windows\notepad.exe` {
		t.Errorf("notepad path = %q, want \\Windows\\notepad.exe", got)
	}
	if got := hInt(t, np, "size"); got != 12345 {
		t.Errorf("notepad size = %d, want 12345", got)
	}
	if got := hInt(t, np, "parent_record"); got != 0 {
		t.Errorf("notepad parent_record = %d, want 0", got)
	}
	if got := hStr(t, np, "si_modified_iso"); got != unixToISO(wantUnix) {
		t.Errorf("si_modified_iso = %q, want %q", got, unixToISO(wantUnix))
	}
	// The sub-second fraction is emitted per timestamp; a whole-second crafted
	// time reports 0 (the feature that powers sub-second timestomping detection).
	if got := hInt(t, np, "si_modified_ns"); got != 0 {
		t.Errorf("si_modified_ns = %d, want 0 (whole-second crafted time)", got)
	}
	if got := hInt(t, np, "fn_created"); got != wantUnix {
		t.Errorf("fn_created = %d, want %d", got, wantUnix)
	}
}

// TestMftParseDetectsNonDefaultRecordSize covers a $MFT formatted with 4096-byte
// records. Striding such a table at the 1024-byte default lands three out of
// every four reads inside a record body, so the parse used to drop ~75% of the
// records and number the survivors as if they were 1024 bytes apart.
func TestMftParseDetectsNonDefaultRecordSize(t *testing.T) {
	const recordSize = 4096
	ft := mftNTFSTime(1500000000)

	mft := make([]byte, 2*recordSize)
	copy(mft[0:], buildMFTRecordSized(recordSize, 0, 1, true, 5, "Windows", 0, ft))
	copy(mft[recordSize:], buildMFTRecordSized(recordSize, 1, 1, false, 0, "notepad.exe", 12345, ft))

	path := filepath.Join(t.TempDir(), "$MFT")
	if err := os.WriteFile(path, mft, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	payload, errObj := unwrapPair(t, MftParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("mft_parse error: %s", errObj.Inspect())
	}
	h := payload.(*object.Hash)

	if got := hInt(t, h, "record_size"); got != recordSize {
		t.Errorf("record_size = %d, want %d", got, recordSize)
	}
	if got := hInt(t, h, "count"); got != 2 {
		t.Fatalf("count = %d, want 2", got)
	}
	if got := hInt(t, h, "skipped"); got != 0 {
		t.Errorf("skipped = %d, want 0", got)
	}

	// Record numbers must come from the real stride, not off/1024.
	np := mftEntryByName(t, hashValueByKey(h, "entries").(*object.Array), "notepad.exe")
	if got := hInt(t, np, "record"); got != 1 {
		t.Errorf("notepad.exe record = %d, want 1", got)
	}
}

func TestMftParseRejectsUnknown(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "random.bin")
	// Not a FILE record, not an NTFS boot sector.
	_ = os.WriteFile(bad, make([]byte, 2048), 0644)
	if _, errObj := unwrapPair(t, MftParse(stringObj(bad))); errObj == nil {
		t.Error("expected error for a non-$MFT, non-volume file")
	}
}
