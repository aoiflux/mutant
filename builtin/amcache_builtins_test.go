package builtin

import (
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

func TestAmcacheParseInventory(t *testing.T) {
	const wantUnix = int64(1700000000)
	filetime := uint64((wantUnix + filetimeEpochDeltaSec) * 10_000_000)

	// Build an Amcache.hve-like tree: <root>\Root\InventoryApplicationFile\<entry>.
	entry := &hiveNode{
		name: "0000abcd",
		values: []hiveKV{
			{name: "LowerCaseLongPath", str: `c:\users\victim\evil.exe`},
			{name: "Name", str: "evil.exe"},
			{name: "FileId", str: "0000da39a3ee5e6b4b0d3255bfef95601890afd80709"},
			{name: "Publisher", str: "Evil Corp"},
			{name: "Version", str: "1.0.0"},
		},
	}
	root := &hiveNode{name: "CMI-CreateHive", children: []*hiveNode{
		{name: "Root", children: []*hiveNode{
			{name: "InventoryApplicationFile", children: []*hiveNode{entry}},
		}},
	}}

	dir := t.TempDir()
	path := filepath.Join(dir, "Amcache.hve")
	if err := os.WriteFile(path, newHiveBuilder(filetime).finish(root), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	payload, errObj := unwrapPair(t, AmcacheParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("amcache_parse error: %s", errObj.Inspect())
	}
	h := payload.(*object.Hash)
	if hStr(t, h, "format") != "inventory_application_file" {
		t.Fatalf("format = %q", hStr(t, h, "format"))
	}
	if hInt(t, h, "count") != 1 {
		t.Fatalf("count = %d", hInt(t, h, "count"))
	}
	entries := h.Pairs[(&object.String{Value: "entries"}).HashKey()].Value.(*object.Array)
	e := entries.Elements[0].(*object.Hash)
	if hStr(t, e, "path") != `c:\users\victim\evil.exe` {
		t.Fatalf("path = %q", hStr(t, e, "path"))
	}
	if hStr(t, e, "name") != "evil.exe" {
		t.Fatalf("name = %q", hStr(t, e, "name"))
	}
	// FileId "0000" prefix stripped -> 40-char SHA-1.
	if hStr(t, e, "sha1") != "da39a3ee5e6b4b0d3255bfef95601890afd80709" {
		t.Fatalf("sha1 = %q", hStr(t, e, "sha1"))
	}
	if hStr(t, e, "publisher") != "Evil Corp" {
		t.Fatalf("publisher = %q", hStr(t, e, "publisher"))
	}
	if hInt(t, e, "last_write") != wantUnix {
		t.Fatalf("last_write = %d", hInt(t, e, "last_write"))
	}

	// a non-Amcache hive errors.
	plain := filepath.Join(dir, "plain.hive")
	_ = os.WriteFile(plain, buildTestHive(filetime), 0644)
	if _, errObj := unwrapPair(t, AmcacheParse(stringObj(plain))); errObj == nil {
		t.Fatal("amcache_parse of a non-Amcache hive should error")
	}
}
