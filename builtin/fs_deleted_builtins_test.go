package builtin

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

// buildDeletedMFTRecord crafts a FILE record with the in-use flag CLEAR (deleted)
// carrying $STANDARD_INFORMATION, $FILE_NAME, and a resident $DATA (0x80) holding
// the given content — the recoverable case fs_deleted targets.
func buildDeletedMFTRecord(recordNum uint32, parentRef uint64, name, content string, ntfsTime uint64) []byte {
	rec := make([]byte, 1024)
	copy(rec[0:4], "FILE")
	binary.LittleEndian.PutUint16(rec[0x04:], 0x30) // USA offset
	binary.LittleEndian.PutUint16(rec[0x06:], 3)    // USA size
	binary.LittleEndian.PutUint16(rec[0x10:], 1)    // sequence
	binary.LittleEndian.PutUint16(rec[0x12:], 1)    // hard link count
	binary.LittleEndian.PutUint16(rec[0x14:], 0x38) // first attribute offset
	binary.LittleEndian.PutUint16(rec[0x16:], 0x00) // flags = 0 → DELETED (not in use)
	binary.LittleEndian.PutUint32(rec[0x1C:], 1024) // allocated size
	binary.LittleEndian.PutUint32(rec[0x2C:], recordNum)

	const usn = 0x0001
	binary.LittleEndian.PutUint16(rec[0x30:], usn)
	binary.LittleEndian.PutUint16(rec[0x32:], 0)
	binary.LittleEndian.PutUint16(rec[0x34:], 0)
	binary.LittleEndian.PutUint16(rec[510:], usn)
	binary.LittleEndian.PutUint16(rec[1022:], usn)

	off := 0x38
	off = mftPutResidentAttr(rec, off, 0x10, mftSIValue(ntfsTime))                                        // $STANDARD_INFORMATION
	off = mftPutResidentAttr(rec, off, 0x30, mftFNValue(parentRef, name, uint64(len(content)), ntfsTime, false)) // $FILE_NAME
	off = mftPutResidentAttr(rec, off, 0x80, []byte(content))                                             // resident $DATA
	binary.LittleEndian.PutUint32(rec[off:], 0xFFFFFFFF)                                                  // end marker
	off += 4
	if off%8 != 0 {
		off += 8 - off%8
	}
	binary.LittleEndian.PutUint32(rec[0x18:], uint32(off)) // used size
	return rec
}

func TestFsDeleted(t *testing.T) {
	ft := mftNTFSTime(1600000000)
	content := "secret recovered text"

	// Record 0: a live directory "docs" (parent = root 5). Record 1: a deleted
	// file "secret.txt" under record 0 with recoverable resident data.
	mft := make([]byte, 2*1024)
	copy(mft[0:], buildMFTRecord(0, 1, true, 5, "docs", 0, ft))
	copy(mft[1024:], buildDeletedMFTRecord(1, 0, "secret.txt", content, ft))

	path := filepath.Join(t.TempDir(), "$MFT")
	if err := os.WriteFile(path, mft, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	payload, errObj := unwrapPair(t, FsDeleted(stringObj(path)))
	if errObj != nil {
		t.Fatalf("fs_deleted error: %s", errObj.Inspect())
	}
	h := payload.(*object.Hash)
	if got := hStr(t, h, "source_type"); got != "mft" {
		t.Errorf("source_type = %q, want mft", got)
	}
	if got := hInt(t, h, "deleted_count"); got != 1 {
		t.Fatalf("deleted_count = %d, want 1 (the live directory must be excluded)", got)
	}
	entries := hashValueByKey(h, "entries").(*object.Array)
	e := entries.Elements[0].(*object.Hash)

	if hStr(t, e, "name") != "secret.txt" {
		t.Errorf("name = %q", hStr(t, e, "name"))
	}
	if hStr(t, e, "path") != `\docs\secret.txt` {
		t.Errorf("path = %q, want \\docs\\secret.txt", hStr(t, e, "path"))
	}
	if !hBoolAt(t, e, "resident") || !hBoolAt(t, e, "recoverable") || !hBoolAt(t, e, "has_data") {
		t.Errorf("recovery flags wrong: %s", e.Inspect())
	}
	if got := hStr(t, e, "resident_data"); got != hex.EncodeToString([]byte(content)) {
		t.Errorf("resident_data = %q, want hex of %q", got, content)
	}
	// Sanity: the hex decodes back to the original content.
	if raw, _ := hex.DecodeString(hStr(t, e, "resident_data")); string(raw) != content {
		t.Errorf("recovered content = %q, want %q", raw, content)
	}
}

func TestFsDeletedRejectsNonMFT(t *testing.T) {
	path := filepath.Join(t.TempDir(), "random.bin")
	_ = os.WriteFile(path, make([]byte, 2048), 0644)
	if _, errObj := unwrapPair(t, FsDeleted(stringObj(path))); errObj == nil {
		t.Error("expected error for a non-$MFT, non-volume file")
	}
}
