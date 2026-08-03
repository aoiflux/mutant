package builtin

import (
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

func TestBodyfileParseAndMactime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "body.txt")
	// One entry: atime=crtime=1700000000, mtime=ctime=1700000100.
	content := "" +
		"# TSK bodyfile\n" +
		"d41d8cd98f00b204e9800998ecf8427e|/etc/passwd|12345-128-1|r/rrw-r--r--|0|0|2048|1700000000|1700000100|1700000100|1700000000\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	parsePayload, errObj := unwrapPair(t, BodyfileParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("bodyfile_parse error: %s", errObj.Inspect())
	}
	entries, ok := parsePayload.(*object.Array)
	if !ok || len(entries.Elements) != 1 {
		t.Fatalf("expected 1 entry, got %s", parsePayload.Inspect())
	}
	e := entries.Elements[0].(*object.Hash)
	if hStr(t, e, "name") != "/etc/passwd" {
		t.Fatalf("name = %q", hStr(t, e, "name"))
	}
	if hStr(t, e, "inode") != "12345-128-1" {
		t.Fatalf("inode should stay a string, got %q", hStr(t, e, "inode"))
	}
	if hInt(t, e, "size") != 2048 || hInt(t, e, "mtime") != 1700000100 {
		t.Fatalf("numeric fields wrong: %s", e.Inspect())
	}

	// mactime: two distinct timestamps for this entry.
	mtPayload := Mactime(entries)
	rows, ok := mtPayload.(*object.Array)
	if !ok || len(rows.Elements) != 2 {
		t.Fatalf("mactime should emit 2 rows, got %s", mtPayload.Inspect())
	}
	r0 := rows.Elements[0].(*object.Hash)
	r1 := rows.Elements[1].(*object.Hash)
	// sorted ascending: 1700000000 (atime+crtime => ".a.b"), then 1700000100 (mtime+ctime => "m.c.").
	if hInt(t, r0, "ts") != 1700000000 || hStr(t, r0, "macb") != ".a.b" {
		t.Fatalf("row0 = ts=%d macb=%q, want 1700000000/.a.b", hInt(t, r0, "ts"), hStr(t, r0, "macb"))
	}
	if hInt(t, r1, "ts") != 1700000100 || hStr(t, r1, "macb") != "m.c." {
		t.Fatalf("row1 = ts=%d macb=%q, want 1700000100/m.c.", hInt(t, r1, "ts"), hStr(t, r1, "macb"))
	}

	// error: mactime on a non-hash entry.
	if _, ok := Mactime(&object.Array{Elements: []object.Object{intObj(1)}}).(*object.Error); !ok {
		t.Fatal("mactime of non-hash entries should error")
	}
}

func hStr(t *testing.T, h *object.Hash, key string) string {
	t.Helper()
	v, ok := hashValueByKey(h, key).(*object.String)
	if !ok {
		t.Fatalf("key %q not a STRING", key)
	}
	return v.Value
}

func hInt(t *testing.T, h *object.Hash, key string) int64 {
	t.Helper()
	v, ok := hashValueByKey(h, key).(*object.Integer)
	if !ok {
		t.Fatalf("key %q not an INTEGER", key)
	}
	return v.Value
}
