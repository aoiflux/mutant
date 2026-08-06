package builtin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"mutant/object"
)

// craftLnk builds a minimal shell link starting with the full LNK signature
// (so parseCustomJumplist's scan finds it), carrying a relative path.
func craftLnk(relPath string) []byte {
	hdr := make([]byte, 76)
	copy(hdr[0:20], lnkHeaderSig)                          // HeaderSize + LinkCLSID
	binary.LittleEndian.PutUint32(hdr[20:24], 0x08|0x80)   // HasRelativePath|IsUnicode
	binary.LittleEndian.PutUint32(hdr[24:28], 0x20)        // FileAttributes
	return append(hdr, unicodeStringData(relPath)...)
}

func TestJumplistCustom(t *testing.T) {
	// A custom jumplist: a small header then two concatenated shell links.
	blob := []byte{0x02, 0x00, 0x00, 0x00} // version-ish header prefix
	blob = append(blob, craftLnk(`..\one.exe`)...)
	blob = append(blob, craftLnk(`..\two.exe`)...)

	path := filepath.Join(t.TempDir(), "app.customDestinations-ms")
	if err := os.WriteFile(path, blob, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	payload, errObj := unwrapPair(t, JumplistParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("jumplist_parse error: %s", errObj.Inspect())
	}
	h := payload.(*object.Hash)
	if got := hStr(t, h, "type"); got != "custom" {
		t.Errorf("type = %q, want custom", got)
	}
	if got := hInt(t, h, "entry_count"); got != 2 {
		t.Fatalf("entry_count = %d, want 2", got)
	}
	entries := hashValueByKey(h, "entries").(*object.Array)
	if got := hStr(t, entries.Elements[0].(*object.Hash), "relative_path"); got != `..\one.exe` {
		t.Errorf("entry0 relative_path = %q", got)
	}
	if got := hStr(t, entries.Elements[1].(*object.Hash), "relative_path"); got != `..\two.exe` {
		t.Errorf("entry1 relative_path = %q", got)
	}
}

// TestParseDestList exercises the version-3 (Win10) DestList entry layout used by
// parseAutomaticJumplist, independently of the OLE container.
func TestParseDestList(t *testing.T) {
	const wantUnix = int64(1600000000)
	ft := uint64((wantUnix + filetimeEpochDeltaSec) * 10_000_000)
	path := `C:\Users\test\file.txt`
	pathU16 := utf16.Encode([]rune(path))

	buf := make([]byte, 32+0x76+len(pathU16)*2+4)
	binary.LittleEndian.PutUint32(buf[0:], 3)  // version 3
	binary.LittleEndian.PutUint32(buf[4:], 1)  // 1 entry
	binary.LittleEndian.PutUint32(buf[8:], 0)  // 0 pinned

	base := 32
	copy(buf[base+0x48:], []byte("MYHOST"))                             // hostname
	binary.LittleEndian.PutUint32(buf[base+0x58:], 5)                   // stream id
	binary.LittleEndian.PutUint64(buf[base+0x64:], ft)                  // last access
	binary.LittleEndian.PutUint32(buf[base+0x6C:], 0)                   // pinned (!=0xFFFFFFFF)
	binary.LittleEndian.PutUint16(buf[base+0x74:], uint16(len(pathU16))) // path size (chars)
	for i, c := range pathU16 {
		binary.LittleEndian.PutUint16(buf[base+0x76+i*2:], c)
	}

	entries := parseDestList(buf)
	if len(entries) != 1 {
		t.Fatalf("parseDestList returned %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.streamID != 5 {
		t.Errorf("streamID = %d, want 5", e.streamID)
	}
	if e.hostname != "MYHOST" {
		t.Errorf("hostname = %q, want MYHOST", e.hostname)
	}
	if e.lastAccess != wantUnix {
		t.Errorf("lastAccess = %d, want %d", e.lastAccess, wantUnix)
	}
	if !e.pinned {
		t.Error("entry should be pinned (pin status 0)")
	}
	if e.path != path {
		t.Errorf("path = %q, want %q", e.path, path)
	}
}

func TestJumplistRejectsGarbage(t *testing.T) {
	// Not a CFB and no embedded links → custom path with zero entries.
	path := filepath.Join(t.TempDir(), "empty.customDestinations-ms")
	_ = os.WriteFile(path, []byte{0x02, 0x00, 0x00, 0x00}, 0644)
	payload, errObj := unwrapPair(t, JumplistParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("jumplist_parse error: %s", errObj.Inspect())
	}
	if got := hInt(t, payload.(*object.Hash), "entry_count"); got != 0 {
		t.Errorf("entry_count = %d, want 0", got)
	}
}

