package builtin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"mutant/object"
)

func unicodeStringData(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	out := make([]byte, 2+len(u16)*2)
	binary.LittleEndian.PutUint16(out[0:2], uint16(len(u16)))
	for i, c := range u16 {
		binary.LittleEndian.PutUint16(out[2+i*2:], c)
	}
	return out
}

func TestLnkParse(t *testing.T) {
	const wantUnix = int64(1700000000)
	filetime := uint64((wantUnix + filetimeEpochDeltaSec) * 10_000_000)

	hdr := make([]byte, 76)
	binary.LittleEndian.PutUint32(hdr[0:4], 0x0000004C) // HeaderSize
	// LinkFlags: HasRelativePath|HasWorkingDir|HasArguments|IsUnicode.
	binary.LittleEndian.PutUint32(hdr[20:24], 0x08|0x10|0x20|0x80)
	binary.LittleEndian.PutUint32(hdr[24:28], 0x20) // FileAttributes (archive)
	binary.LittleEndian.PutUint64(hdr[28:36], filetime) // CreationTime
	binary.LittleEndian.PutUint64(hdr[36:44], 0)        // AccessTime (unset)
	binary.LittleEndian.PutUint64(hdr[44:52], filetime) // WriteTime
	binary.LittleEndian.PutUint32(hdr[52:56], 4096)     // FileSize
	binary.LittleEndian.PutUint32(hdr[60:64], 1)        // ShowCommand

	blob := hdr
	blob = append(blob, unicodeStringData(`..\payload.exe`)...) // RelativePath
	blob = append(blob, unicodeStringData(`C:\Users\victim`)...) // WorkingDir
	blob = append(blob, unicodeStringData(`-q -x`)...)           // Arguments

	dir := t.TempDir()
	path := filepath.Join(dir, "shortcut.lnk")
	if err := os.WriteFile(path, blob, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	payload, errObj := unwrapPair(t, LnkParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("lnk_parse error: %s", errObj.Inspect())
	}
	h := payload.(*object.Hash)

	if hInt(t, h, "creation_time") != wantUnix || hInt(t, h, "write_time") != wantUnix {
		t.Fatalf("timestamps: creation=%d write=%d", hInt(t, h, "creation_time"), hInt(t, h, "write_time"))
	}
	if hInt(t, h, "access_time") != 0 {
		t.Fatal("unset FILETIME should map to unix 0")
	}
	if hStr(t, h, "creation_iso") != "2023-11-14T22:13:20Z" {
		t.Fatalf("creation_iso = %q", hStr(t, h, "creation_iso"))
	}
	if hStr(t, h, "relative_path") != `..\payload.exe` {
		t.Fatalf("relative_path = %q", hStr(t, h, "relative_path"))
	}
	if hStr(t, h, "working_dir") != `C:\Users\victim` {
		t.Fatalf("working_dir = %q", hStr(t, h, "working_dir"))
	}
	if hStr(t, h, "arguments") != "-q -x" {
		t.Fatalf("arguments = %q", hStr(t, h, "arguments"))
	}
	if !hBoolAt(t, h, "is_unicode") {
		t.Fatal("is_unicode should be true")
	}
	decoded := h.Pairs[(&object.String{Value: "link_flags_decoded"}).HashKey()].Value.(*object.Array)
	if len(decoded.Elements) < 4 {
		t.Fatalf("expected several decoded flags, got %s", decoded.Inspect())
	}

	// A non-LNK file errors.
	bad := filepath.Join(dir, "bad.bin")
	_ = os.WriteFile(bad, []byte("not a lnk file at all"), 0644)
	if _, errObj := unwrapPair(t, LnkParse(stringObj(bad))); errObj == nil {
		t.Fatal("lnk_parse of a non-LNK file should error")
	}
}

func hBoolAt(t *testing.T, h *object.Hash, key string) bool {
	t.Helper()
	v, ok := hashValueByKey(h, key).(*object.Boolean)
	if !ok {
		t.Fatalf("key %q not a BOOLEAN", key)
	}
	return v.Value
}
