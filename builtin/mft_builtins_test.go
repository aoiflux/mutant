package builtin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"mutant/object"
)

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
	rec := make([]byte, 1024)
	copy(rec[0:4], "FILE")
	const usaOff, usaSize = 0x30, 3 // USN + 2 sector fixups (1024/512)
	binary.LittleEndian.PutUint16(rec[0x04:], usaOff)
	binary.LittleEndian.PutUint16(rec[0x06:], usaSize)
	binary.LittleEndian.PutUint16(rec[0x10:], seq)
	binary.LittleEndian.PutUint16(rec[0x12:], 1) // hard link count
	binary.LittleEndian.PutUint16(rec[0x14:], 0x38)
	flags := uint16(0x01)
	if isDir {
		flags |= 0x02
	}
	binary.LittleEndian.PutUint16(rec[0x16:], flags)
	binary.LittleEndian.PutUint32(rec[0x1C:], 1024) // allocated size
	binary.LittleEndian.PutUint32(rec[0x2C:], recordNum)

	// Update sequence array. Attributes live well before offset 510, so writing
	// the USN at the sector ends doesn't touch them.
	const usn = 0x0001
	binary.LittleEndian.PutUint16(rec[usaOff:], usn)   // USA[0] = USN
	binary.LittleEndian.PutUint16(rec[usaOff+2:], 0)   // USA[1] = sector0 real bytes
	binary.LittleEndian.PutUint16(rec[usaOff+4:], 0)   // USA[2] = sector1 real bytes
	binary.LittleEndian.PutUint16(rec[510:], usn)      // sector0 end
	binary.LittleEndian.PutUint16(rec[1022:], usn)     // sector1 end

	off := 0x38
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
	if got := hInt(t, np, "fn_created"); got != wantUnix {
		t.Errorf("fn_created = %d, want %d", got, wantUnix)
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
