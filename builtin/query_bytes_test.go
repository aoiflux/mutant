package builtin

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/Velocidex/ordereddict"

	"mutant/object"
)

// blobBytes reads one column that must have come back as a buffer.
func blobBytes(t *testing.T, h *object.Hash, key string) []byte {
	t.Helper()
	value := hashValueByKey(h, key)
	buf, ok := value.(*object.Bytes)
	if !ok {
		t.Fatalf("%s is %s (%s), want BYTES", key, value.Type(), value.Inspect())
	}
	return buf.Value
}

func queryRowsBytes(t *testing.T, path, query string) []*object.Hash {
	t.Helper()
	payload, errObj := unwrapPair(t, SqliteQueryBytes(stringObj(path), stringObj(query)))
	if errObj != nil {
		t.Fatalf("sqlite_query_bytes: %s", errObj.Inspect())
	}
	rows := hashValueByKey(payload.(*object.Hash), "rows").(*object.Array)
	if len(rows.Elements) == 0 {
		t.Fatal("the query returned no rows; the test proves nothing")
	}
	out := make([]*object.Hash, len(rows.Elements))
	for i, row := range rows.Elements {
		out[i] = row.(*object.Hash)
	}
	return out
}

// The two builtins have to disagree about a BLOB and agree about everything
// else, so this asks both the same question and compares the answers.
//
// Row 2's blob is X'414243' -- the bytes of "ABC", and so valid UTF-8. That is
// the row worth having: sqlite_query returns it as the string "ABC" while row 1's
// X'00FF' comes back as the hex "00ff", which is the whole defect. One column,
// two representations, chosen by the content rather than the column type, and no
// way for a caller to tell a BLOB that happened to decode from a TEXT that did
// not. sqlite_query_bytes answers BYTES for both.
func TestSqliteQueryBytesDiffersFromSqliteQueryOnlyOnBlobs(t *testing.T) {
	path := makeTestDB(t)
	const query = "SELECT id, name, score, data, note FROM items ORDER BY id"

	textPayload, errObj := unwrapPair(t, SqliteQuery(stringObj(path), stringObj(query)))
	if errObj != nil {
		t.Fatalf("sqlite_query: %s", errObj.Inspect())
	}
	textRows := hashValueByKey(textPayload.(*object.Hash), "rows").(*object.Array)
	byteRows := queryRowsBytes(t, path, query)

	if len(textRows.Elements) != len(byteRows) {
		t.Fatalf("row counts differ: %d vs %d", len(textRows.Elements), len(byteRows))
	}

	wantBlobs := [][]byte{{0x00, 0xFF}, {'A', 'B', 'C'}}
	for i, want := range wantBlobs {
		if got := string(blobBytes(t, byteRows[i], "data")); got != string(want) {
			t.Errorf("row %d data = %x, want %x", i, got, want)
		}
	}

	// The unchanged builtin still splits on content, which is what makes the new
	// one worth having. If this ever stops holding, the default flipped and that
	// was meant to be a deliberate, separate change.
	textRow0 := textRows.Elements[0].(*object.Hash)
	textRow1 := textRows.Elements[1].(*object.Hash)
	if got := hStr(t, textRow0, "data"); got != "00ff" {
		t.Errorf("sqlite_query row 0 data = %q, want the hex 00ff", got)
	}
	if got := hStr(t, textRow1, "data"); got != "ABC" {
		t.Errorf("sqlite_query row 1 data = %q, want the string ABC", got)
	}

	// Every other column has to be untouched, or this is not a BLOB change.
	for i, byteRow := range byteRows {
		textRow := textRows.Elements[i].(*object.Hash)
		for _, column := range []string{"id", "name", "score", "note"} {
			want := hashValueByKey(textRow, column)
			got := hashValueByKey(byteRow, column)
			if got.Type() != want.Type() || got.Inspect() != want.Inspect() {
				t.Errorf("row %d %s = %s %s, want %s %s",
					i, column, got.Type(), got.Inspect(), want.Type(), want.Inspect())
			}
		}
	}
}

// An empty BLOB is a buffer too. Under sqlite_query it is indistinguishable from
// an empty TEXT, because both render as "".
func TestSqliteQueryBytesReturnsEmptyBlobAsAnEmptyBuffer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE t (b BLOB); INSERT INTO t VALUES (X'');`); err != nil {
		db.Close()
		t.Fatalf("exec: %v", err)
	}
	db.Close()

	rows := queryRowsBytes(t, path, "SELECT b FROM t")
	if got := blobBytes(t, rows[0], "b"); len(got) != 0 {
		t.Errorf("b = %x, want an empty buffer", got)
	}
}

// The buffers are handed back without a copy, on the strength of database/sql
// cloning a []byte into an *any destination. An *object.Bytes is mutable from a
// script, so if that were wrong, writing to one row's blob would reach into
// another's. This writes to the first row and reads the rest.
func TestSqliteQueryBytesRowsDoNotShareOneBuffer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blobs.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE t (id INTEGER, b BLOB);
		INSERT INTO t VALUES (1, X'AAAAAAAA');
		INSERT INTO t VALUES (2, X'BBBBBBBB');
		INSERT INTO t VALUES (3, X'CCCCCCCC');`); err != nil {
		db.Close()
		t.Fatalf("exec: %v", err)
	}
	db.Close()

	rows := queryRowsBytes(t, path, "SELECT id, b FROM t ORDER BY id")
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}

	first := blobBytes(t, rows[0], "b")
	if len(first) != 4 {
		t.Fatalf("row 0 blob is %d bytes, want 4; the write below would be a no-op", len(first))
	}
	for i := range first {
		first[i] = 0
	}

	for i, want := range []byte{0xBB, 0xCC} {
		got := blobBytes(t, rows[i+1], "b")
		for _, b := range got {
			if b != want {
				t.Fatalf("after writing to row 0, row %d holds %x, want every byte %02x",
					i+1, got, want)
			}
		}
	}
}

// evtxValue is one walk shared by evtx_parse and evtx_parse_bytes, so binary has
// to change and nothing else may.
func TestEvtxValueRendersBinaryBothWays(t *testing.T) {
	raw := []byte{0xDE, 0xAD, 0x00, 0xBE, 0xEF}

	if got, ok := evtxValue(raw, false).(*object.String); !ok || got.Value != "dead00beef" {
		t.Errorf("evtx_parse rendering = %s, want the hex dead00beef", evtxValue(raw, false).Inspect())
	}
	got, ok := evtxValue(raw, true).(*object.Bytes)
	if !ok {
		t.Fatalf("evtx_parse_bytes rendering = %s, want BYTES", evtxValue(raw, true).Type())
	}
	if string(got.Value) != string(raw) {
		t.Errorf("bytes = %x, want %x", got.Value, raw)
	}
}

// Binary in an EVTX record is nested inside the event tree rather than sitting at
// a key we chose, which is why this is a separate builtin and not an extra field.
// The flag has to survive the descent through both container arms.
func TestEvtxValueCarriesRawBinaryIntoNestedContainers(t *testing.T) {
	raw := []byte{0x01, 0x02, 0x03}
	tree := ordereddict.NewDict().
		Set("EventData", ordereddict.NewDict().
			Set("Data", []interface{}{"text", raw}).
			Set("Name", "Binary")).
		Set("Count", 2)

	hash, ok := evtxValue(tree, true).(*object.Hash)
	if !ok {
		t.Fatalf("tree rendered as %s, want a hash", evtxValue(tree, true).Type())
	}
	data := hashValueByKey(hashValueByKey(hash, "EventData").(*object.Hash), "Data").(*object.Array)

	if s, ok := data.Elements[0].(*object.String); !ok || s.Value != "text" {
		t.Errorf("sibling string became %s, want an untouched STRING", data.Elements[0].Type())
	}
	buf, ok := data.Elements[1].(*object.Bytes)
	if !ok {
		t.Fatalf("nested binary is %s, want BYTES", data.Elements[1].Type())
	}
	if string(buf.Value) != string(raw) {
		t.Errorf("nested bytes = %x, want %x", buf.Value, raw)
	}

	// The same tree through evtx_parse still hex-encodes, at the same depth.
	plain := evtxValue(tree, false).(*object.Hash)
	plainData := hashValueByKey(hashValueByKey(plain, "EventData").(*object.Hash), "Data").(*object.Array)
	if s, ok := plainData.Elements[1].(*object.String); !ok || s.Value != "010203" {
		t.Errorf("evtx_parse nested binary = %s, want the hex 010203", plainData.Elements[1].Inspect())
	}
}

// The bytes evtx hands over are a window onto the parsed chunk, shared with
// every other value in it, so evtxValue has to copy before wrapping them in
// something a script can write to. Deleting the copy makes this fail.
func TestEvtxValueDoesNotAliasItsInput(t *testing.T) {
	raw := []byte{0x11, 0x22, 0x33, 0x44}

	buf, ok := evtxValue(raw, true).(*object.Bytes)
	if !ok {
		t.Fatalf("rendered as %s, want BYTES", evtxValue(raw, true).Type())
	}
	for i := range buf.Value {
		buf.Value[i] = 0xFF
	}

	if string(raw) != string([]byte{0x11, 0x22, 0x33, 0x44}) {
		t.Errorf("writing to the returned buffer reached the parser's: %x", raw)
	}
}
