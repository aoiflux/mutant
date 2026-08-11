package builtin

import (
	"database/sql"
	"path/filepath"
	"testing"

	"mutant/object"
)

func makeTestDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	stmts := `
		CREATE TABLE items (id INTEGER, name TEXT, score REAL, data BLOB, note TEXT);
		INSERT INTO items VALUES (1, 'alpha', 1.5, X'00FF', NULL);
		INSERT INTO items VALUES (2, 'beta', 2.5, X'414243', 'hi');`
	if _, err := db.Exec(stmts); err != nil {
		t.Fatalf("exec: %v", err)
	}
	return path
}

func TestSqliteQuery(t *testing.T) {
	path := makeTestDB(t)

	payload, errObj := unwrapPair(t, SqliteQuery(stringObj(path), stringObj("SELECT id, name, score, data, note FROM items ORDER BY id")))
	if errObj != nil {
		t.Fatalf("sqlite_query error: %s", errObj.Inspect())
	}
	h := payload.(*object.Hash)
	if got := hInt(t, h, "row_count"); got != 2 {
		t.Fatalf("row_count = %d, want 2", got)
	}
	if hBoolAt(t, h, "truncated") {
		t.Error("should not be truncated")
	}
	cols := hashValueByKey(h, "columns").(*object.Array)
	if len(cols.Elements) != 5 || cols.Elements[0].(*object.String).Value != "id" {
		t.Fatalf("columns = %s", cols.Inspect())
	}

	rows := hashValueByKey(h, "rows").(*object.Array)
	r0 := rows.Elements[0].(*object.Hash)
	if hInt(t, r0, "id") != 1 || hStr(t, r0, "name") != "alpha" {
		t.Errorf("r0 id/name = %d/%q", hInt(t, r0, "id"), hStr(t, r0, "name"))
	}
	if f, ok := hashValueByKey(r0, "score").(*object.Float); !ok || f.Value != 1.5 {
		t.Errorf("r0 score = %v", hashValueByKey(r0, "score"))
	}
	if hStr(t, r0, "data") != "00ff" { // non-UTF8 blob → hex
		t.Errorf("r0 data = %q, want 00ff", hStr(t, r0, "data"))
	}
	if _, ok := hashValueByKey(r0, "note").(*object.Null); !ok {
		t.Errorf("r0 note should be NULL, got %T", hashValueByKey(r0, "note"))
	}

	r1 := rows.Elements[1].(*object.Hash)
	if hStr(t, r1, "data") != "ABC" { // UTF-8 blob → string
		t.Errorf("r1 data = %q, want ABC", hStr(t, r1, "data"))
	}
	if hStr(t, r1, "note") != "hi" {
		t.Errorf("r1 note = %q", hStr(t, r1, "note"))
	}
}

func TestSqliteQueryParams(t *testing.T) {
	path := makeTestDB(t)
	payload, errObj := unwrapPair(t, SqliteQuery(
		stringObj(path),
		stringObj("SELECT name FROM items WHERE id = ?"),
		&object.Array{Elements: []object.Object{intObj(2)}},
	))
	if errObj != nil {
		t.Fatalf("sqlite_query params error: %s", errObj.Inspect())
	}
	rows := hashValueByKey(payload.(*object.Hash), "rows").(*object.Array)
	if len(rows.Elements) != 1 || hStr(t, rows.Elements[0].(*object.Hash), "name") != "beta" {
		t.Fatalf("param query returned %s", rows.Inspect())
	}
}

func TestSqliteQueryErrors(t *testing.T) {
	path := makeTestDB(t)
	// Bad SQL.
	if _, e := unwrapPair(t, SqliteQuery(stringObj(path), stringObj("SELECT * FROM nonexistent"))); e == nil {
		t.Error("expected error for a bad query")
	}
	// Missing file.
	if _, e := unwrapPair(t, SqliteQuery(stringObj(filepath.Join(t.TempDir(), "nope.db")), stringObj("SELECT 1"))); e == nil {
		t.Error("expected error for a missing database")
	}
	// Wrong arg count.
	if _, e := unwrapPair(t, SqliteQuery(stringObj(path))); e == nil {
		t.Error("expected arg-count error")
	}
	// Non-array params.
	if _, e := unwrapPair(t, SqliteQuery(stringObj(path), stringObj("SELECT 1"), intObj(5))); e == nil {
		t.Error("expected error for non-array params")
	}
}
