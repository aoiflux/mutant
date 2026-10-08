package builtin

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// sqliteFixture writes a database holding what stmts create.
func sqliteFixture(t *testing.T, stmts string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(stmts); err != nil {
		t.Fatalf("exec: %v", err)
	}
	return path
}

func sqliteRows(t *testing.T, result object.Object) []object.Object {
	t.Helper()
	return mustArray(t, hashField(t, result, "rows")).Elements
}

// M26-DAT-023. A buffer was bound as its hex text, which can never equal a
// BLOB, so looking a key or a hash up by its bytes always answered "not
// present".
func TestSqliteBindsBytesAsABlob(t *testing.T) {
	path := sqliteFixture(t, "CREATE TABLE k (key BLOB); INSERT INTO k VALUES (X'DEADBEEF');")
	result := mustCall(t, SqliteQueryBytes, str(path), str("SELECT typeof(?1) AS t, count(*) AS n FROM k WHERE key = ?1"),
		&object.Array{Elements: []object.Object{&object.Bytes{Value: []byte{0xde, 0xad, 0xbe, 0xef}}}})
	row := sqliteRows(t, result)[0]
	if got := hashStr(t, row, "t"); got != "blob" {
		t.Errorf("the buffer bound as %s, want blob", got)
	}
	if got := hashInt(t, row, "n"); got != 1 {
		t.Errorf("WHERE key = the buffer matched %d rows, want 1", got)
	}
}

// A value with no SQLite type was bound as the text it prints as.
func TestSqliteRefusesAParameterWithNoSQLiteType(t *testing.T) {
	path := sqliteFixture(t, "CREATE TABLE k (key TEXT);")
	errObj := callErr(t, SqliteQuery, str(path), str("SELECT * FROM k WHERE key = ?1"),
		&object.Array{Elements: []object.Object{&object.Array{Elements: []object.Object{str("a")}}}})
	if !strings.Contains(errObj.Message, "parameter 1: a ARRAY has no SQLite type") {
		t.Errorf("got %q", errObj.Message)
	}
}

// A row is a hash keyed by column name, so of two columns with one name the
// row kept the second's value while the column list named both.
func TestSqliteRefusesTwoColumnsOfOneName(t *testing.T) {
	path := sqliteFixture(t, "CREATE TABLE a (id INTEGER); CREATE TABLE b (id INTEGER); INSERT INTO a VALUES (1); INSERT INTO b VALUES (2);")
	errObj := callErr(t, SqliteQuery, str(path), str("SELECT * FROM a JOIN b"))
	if !strings.Contains(errObj.Message, `two columns named "id"`) {
		t.Errorf("got %q", errObj.Message)
	}
	rows := sqliteRows(t, mustCall(t, SqliteQuery, str(path), str("SELECT a.id AS a_id, b.id AS b_id FROM a JOIN b")))
	if hashInt(t, rows[0], "a_id") != 1 || hashInt(t, rows[0], "b_id") != 2 {
		t.Errorf("aliased join = %s", rows[0].Inspect())
	}
}

// M26-DAT-024. TEXT in a DATETIME column came back moved to UTC and cut to the
// second. It keeps its fraction and its offset now; text written with no
// offset is UTC, as SQLite's own date functions read it; and CAST returns the
// text as stored.
func TestSqliteKeepsADatetimesFractionAndOffset(t *testing.T) {
	path := sqliteFixture(t, "CREATE TABLE e (ts DATETIME); "+
		"INSERT INTO e VALUES ('2024-01-02 03:04:05.678+05:30'); INSERT INTO e VALUES ('2024-01-02 03:04:05');")
	rows := sqliteRows(t, mustCall(t, SqliteQuery, str(path), str("SELECT ts, CAST(ts AS TEXT) AS raw FROM e ORDER BY rowid")))
	for i, want := range []struct{ ts, raw string }{
		{"2024-01-02T03:04:05.678+05:30", "2024-01-02 03:04:05.678+05:30"},
		{"2024-01-02T03:04:05Z", "2024-01-02 03:04:05"},
	} {
		if got := hashStr(t, rows[i], "ts"); got != want.ts {
			t.Errorf("row %d: ts = %q, want %q", i, got, want.ts)
		}
		if got := hashStr(t, rows[i], "raw"); got != want.raw {
			t.Errorf("row %d: CAST(ts AS TEXT) = %q, want the text as stored", i, got)
		}
	}
}
