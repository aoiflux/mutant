package builtin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"mutant/object"
)

// buildWin10Shimcache assembles a Win10 AppCompatCache blob with "10ts" entries.
func buildWin10Shimcache(paths []string, filetime uint64) []byte {
	blob := make([]byte, 0x34)
	binary.LittleEndian.PutUint32(blob[0:4], 0x34) // header size

	for _, p := range paths {
		u16 := utf16.Encode([]rune(p))
		pathBytes := make([]byte, len(u16)*2)
		for i, c := range u16 {
			binary.LittleEndian.PutUint16(pathBytes[i*2:], c)
		}
		body := make([]byte, 0)
		ps := make([]byte, 2)
		binary.LittleEndian.PutUint16(ps, uint16(len(pathBytes)))
		body = append(body, ps...)
		body = append(body, pathBytes...)
		ft := make([]byte, 8)
		binary.LittleEndian.PutUint64(ft, filetime)
		body = append(body, ft...)
		body = append(body, 0, 0, 0, 0) // DataSize = 0

		entry := append([]byte("10ts"), 0, 0, 0, 0) // signature + unknown
		cs := make([]byte, 4)
		binary.LittleEndian.PutUint32(cs, uint32(len(body)))
		entry = append(entry, cs...)
		entry = append(entry, body...)
		blob = append(blob, entry...)
	}
	return blob
}

func shimEntries(t *testing.T, res object.Object) *object.Array {
	t.Helper()
	payload, errObj := unwrapPair(t, res)
	if errObj != nil {
		t.Fatalf("shimcache_parse error: %s", errObj.Inspect())
	}
	h := payload.(*object.Hash)
	return h.Pairs[(&object.String{Value: "entries"}).HashKey()].Value.(*object.Array)
}

func TestShimcacheParse(t *testing.T) {
	const wantUnix = int64(1700000000)
	filetime := uint64((wantUnix + filetimeEpochDeltaSec) * 10_000_000)
	paths := []string{`C:\Windows\System32\evil.exe`, `C:\temp\payload.exe`}
	blob := buildWin10Shimcache(paths, filetime)

	dir := t.TempDir()

	// 1) Raw blob file.
	rawPath := filepath.Join(dir, "appcompat.bin")
	if err := os.WriteFile(rawPath, blob, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries := shimEntries(t, ShimcacheParse(stringObj(rawPath)))
	if len(entries.Elements) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries.Elements))
	}
	e0 := entries.Elements[0].(*object.Hash)
	if hStr(t, e0, "path") != `C:\Windows\System32\evil.exe` {
		t.Fatalf("entry0 path = %q", hStr(t, e0, "path"))
	}
	if hInt(t, e0, "last_modified") != wantUnix {
		t.Fatalf("entry0 last_modified = %d", hInt(t, e0, "last_modified"))
	}
	if hInt(t, e0, "position") != 0 || hInt(t, entries.Elements[1].(*object.Hash), "position") != 1 {
		t.Fatal("positions should be 0,1")
	}

	// 2) Inside a SYSTEM hive (ControlSet001\Control\Session Manager\AppCompatCache).
	sysHive := newHiveBuilder(filetime).finish(&hiveNode{name: "CMI", children: []*hiveNode{
		{name: "ControlSet001", children: []*hiveNode{
			{name: "Control", children: []*hiveNode{
				{name: "Session Manager", children: []*hiveNode{
					{name: "AppCompatCache", values: []hiveKV{
						{name: "AppCompatCache", bin: blob, isBin: true},
					}},
				}},
			}},
		}},
	}})
	hivePath := filepath.Join(dir, "SYSTEM")
	if err := os.WriteFile(hivePath, sysHive, 0644); err != nil {
		t.Fatalf("write hive: %v", err)
	}
	hiveEntries := shimEntries(t, ShimcacheParse(stringObj(hivePath)))
	if len(hiveEntries.Elements) != 2 {
		t.Fatalf("hive: expected 2 entries, got %d", len(hiveEntries.Elements))
	}
	if hStr(t, hiveEntries.Elements[1].(*object.Hash), "path") != `C:\temp\payload.exe` {
		t.Fatalf("hive entry1 path = %q", hStr(t, hiveEntries.Elements[1].(*object.Hash), "path"))
	}

	// 3) Unsupported format errors honestly.
	badPath := filepath.Join(dir, "bad.bin")
	badBlob := make([]byte, 16)
	binary.LittleEndian.PutUint32(badBlob[0:4], 0x99) // not a known header
	_ = os.WriteFile(badPath, badBlob, 0644)
	if _, errObj := unwrapPair(t, ShimcacheParse(stringObj(badPath))); errObj == nil {
		t.Fatal("unsupported shimcache format should error")
	}
}
