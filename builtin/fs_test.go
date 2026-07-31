package builtin

import (
	"path/filepath"
	"testing"

	"mutant/object"
)

func fsBool(t *testing.T, res object.Object) bool {
	t.Helper()
	payload, errObj := unwrapPair(t, res)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}
	b, ok := payload.(*object.Boolean)
	if !ok {
		t.Fatalf("expected BOOLEAN, got %T (%s)", payload, payload.Inspect())
	}
	return b.Value
}

func fsStr(t *testing.T, res object.Object) string {
	t.Helper()
	payload, errObj := unwrapPair(t, res)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}
	s, ok := payload.(*object.String)
	if !ok {
		t.Fatalf("expected STRING, got %T (%s)", payload, payload.Inspect())
	}
	return s.Value
}

func TestFsLifecycle(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.txt")

	if !fsBool(t, FsWrite(stringObj(p), stringObj("hello"))) {
		t.Fatal("fs_write should return true")
	}
	if !fsBool(t, FsExists(stringObj(p))) {
		t.Fatal("fs_exists should be true after write")
	}
	if got := fsStr(t, FsRead(stringObj(p))); got != "hello" {
		t.Fatalf("fs_read = %q", got)
	}

	if !fsBool(t, FsAppend(stringObj(p), stringObj(" world"))) {
		t.Fatal("fs_append should return true")
	}
	if got := fsStr(t, FsRead(stringObj(p))); got != "hello world" {
		t.Fatalf("fs_read after append = %q", got)
	}

	// stat returns a hash.
	statPayload, errObj := unwrapPair(t, FsStat(stringObj(p)))
	if errObj != nil {
		t.Fatalf("fs_stat error: %s", errObj.Inspect())
	}
	if _, ok := statPayload.(*object.Hash); !ok {
		t.Fatalf("fs_stat payload type: %T", statPayload)
	}

	// copy then move.
	q := filepath.Join(dir, "b.txt")
	if !fsBool(t, FsCopy(stringObj(p), stringObj(q))) {
		t.Fatal("fs_copy should return true")
	}
	if got := fsStr(t, FsRead(stringObj(q))); got != "hello world" {
		t.Fatalf("fs_read of copy = %q", got)
	}
	moved := filepath.Join(dir, "c.txt")
	if !fsBool(t, FsMove(stringObj(q), stringObj(moved))) {
		t.Fatal("fs_move should return true")
	}
	if fsBool(t, FsExists(stringObj(q))) {
		t.Fatal("source should not exist after move")
	}
	if !fsBool(t, FsExists(stringObj(moved))) {
		t.Fatal("dest should exist after move")
	}

	// mkdir.
	sub := filepath.Join(dir, "sub", "nested")
	if !fsBool(t, FsMkdir(stringObj(sub))) {
		t.Fatal("fs_mkdir should return true")
	}
	if !fsBool(t, FsExists(stringObj(sub))) {
		t.Fatal("mkdir path should exist")
	}

	// list the dir.
	listPayload, errObj := unwrapPair(t, FsList(stringObj(dir)))
	if errObj != nil {
		t.Fatalf("fs_list error: %s", errObj.Inspect())
	}
	listArr, ok := listPayload.(*object.Array)
	if !ok || len(listArr.Elements) == 0 {
		t.Fatalf("fs_list should return a non-empty array, got %T", listPayload)
	}

	// delete.
	if !fsBool(t, FsDelete(stringObj(p))) {
		t.Fatal("fs_delete should return true")
	}
	if fsBool(t, FsExists(stringObj(p))) {
		t.Fatal("file should not exist after delete")
	}
}

func TestFsErrors(t *testing.T) {
	dir := t.TempDir()
	// reading a missing file errors.
	if _, errObj := unwrapPair(t, FsRead(stringObj(filepath.Join(dir, "nope")))); errObj == nil {
		t.Fatal("fs_read of a missing file should error")
	}
	// type errors.
	if _, errObj := unwrapPair(t, FsRead(intObj(1))); errObj == nil {
		t.Fatal("fs_read of non-string should error")
	}
	if _, errObj := unwrapPair(t, FsWrite(stringObj("x"))); errObj == nil {
		t.Fatal("fs_write with wrong arg count should error")
	}
}
