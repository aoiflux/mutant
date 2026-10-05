package builtin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unicode/utf16"

	"mutant/object"
)

// craftLnk builds a minimal shell link starting with the full LNK signature
// (so parseCustomJumplist's scan finds it), carrying a relative path.
func craftLnk(relPath string) []byte {
	hdr := make([]byte, 76)
	copy(hdr[0:20], lnkHeaderSig)                        // HeaderSize + LinkCLSID
	binary.LittleEndian.PutUint32(hdr[20:24], 0x08|0x80) // HasRelativePath|IsUnicode
	binary.LittleEndian.PutUint32(hdr[24:28], 0x20)      // FileAttributes
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

// destListFixtureEntry is one DestList entry as libyal's dtformats and JLECmd's
// DestListEntry lay it out. Version 1 (Windows 7 and 8) puts the path size at
// 0x70. Every later version puts four unknown bytes at 0x70, the access count at
// 0x74, eight unknown bytes at 0x78 and the path size at 0x80, and ends with
// four bytes after the path.
//
// The offsets are written out here rather than taken from the parser's
// constants, so the test states the format and the parser is held to it. The
// test this replaces wrote the path size at 0x74, the offset the parser read,
// and so passed on the defect it was there to catch.
type destListFixtureEntry struct {
	streamID    uint32
	host        string
	unix        int64
	pin         uint32
	accessCount uint32
	path        string
}

func destListFixture(version uint32, pinned uint32, entries ...destListFixtureEntry) []byte {
	buf := make([]byte, 32)
	binary.LittleEndian.PutUint32(buf[0:], version)
	binary.LittleEndian.PutUint32(buf[4:], uint32(len(entries)))
	binary.LittleEndian.PutUint32(buf[8:], pinned)
	for _, fe := range entries {
		u16 := utf16.Encode([]rune(fe.path))
		sizeAt, trailer := 0x70, 0
		if version >= 2 {
			sizeAt, trailer = 0x80, 4
		}
		e := make([]byte, sizeAt+2+len(u16)*2+trailer)
		copy(e[0x48:0x58], fe.host)
		binary.LittleEndian.PutUint32(e[0x58:], fe.streamID)
		binary.LittleEndian.PutUint64(e[0x64:], uint64((fe.unix+filetimeEpochDeltaSec)*10_000_000))
		binary.LittleEndian.PutUint32(e[0x6C:], fe.pin)
		if version >= 2 {
			binary.LittleEndian.PutUint32(e[0x70:], 0xFFFFFFFF)
			binary.LittleEndian.PutUint32(e[0x74:], fe.accessCount)
		}
		binary.LittleEndian.PutUint16(e[sizeAt:], uint16(len(u16)))
		for i, c := range u16 {
			binary.LittleEndian.PutUint16(e[sizeAt+2+i*2:], c)
		}
		if trailer > 0 {
			binary.LittleEndian.PutUint32(e[len(e)-4:], 0x0000DEAD)
		}
		buf = append(buf, e...)
	}
	return buf
}

// TestParseDestListReadsEveryEntryOfEveryVersion is M26-ART-001's regression
// test. Two entries per version, so a misread path size shows twice: once as a
// wrong path, and once as a second entry looked for at the wrong offset. Each
// access count is nonzero and short, which is what the old read at 0x74 took
// for a path length.
func TestParseDestListReadsEveryEntryOfEveryVersion(t *testing.T) {
	want := []destListFixtureEntry{
		{streamID: 5, host: "MYHOST", unix: 1600000000, pin: 0, accessCount: 7, path: `C:\Users\test\file.txt`},
		{streamID: 9, host: "OTHER-PC", unix: 1700000000, pin: 0xFFFFFFFF, accessCount: 3, path: `D:\evidence\notes.docx`},
	}
	for _, version := range []uint32{1, 2, 3, 4, 6} {
		got := parseDestList(destListFixture(version, 1, want...))
		if len(got) != len(want) {
			t.Errorf("version %d: %d entries, want %d", version, len(got), len(want))
			continue
		}
		for i, w := range want {
			g := got[i]
			if g.streamID != w.streamID || g.hostname != w.host || g.lastAccess != w.unix ||
				g.pinned != (w.pin != 0xFFFFFFFF) || g.path != w.path {
				t.Errorf("version %d entry %d = {stream %d, host %q, time %d, pinned %v, path %q}, want {stream %d, host %q, time %d, pinned %v, path %q}",
					version, i, g.streamID, g.hostname, g.lastAccess, g.pinned, g.path,
					w.streamID, w.host, w.unix, w.pin != 0xFFFFFFFF, w.path)
			}
		}
	}
}

// TestParseDestListIsNotSizedByItsCount is the DestList half of M26-ART-005: a
// header whose entry count is far larger than the stream allocates by what the
// stream can hold, not by the count. Sized by the count, 2^24 entries are 900
// MiB before the first is read.
func TestParseDestListIsNotSizedByItsCount(t *testing.T) {
	buf := destListFixture(4, 0, destListFixtureEntry{streamID: 1, host: "H", unix: 1600000000, path: `C:\a`})
	binary.LittleEndian.PutUint32(buf[4:], 1<<24)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got := parseDestList(buf)
	runtime.ReadMemStats(&after)

	if len(got) != 1 || got[0].path != `C:\a` {
		t.Fatalf("parseDestList = %+v, want the one entry the stream holds", got)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
		t.Errorf("parseDestList allocated %d bytes for a %d-byte stream claiming 2^24 entries", grew, len(buf))
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
