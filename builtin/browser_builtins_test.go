package builtin

import (
	"database/sql"
	"path/filepath"
	"strconv"
	"testing"

	"mutant/object"
)

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func makeDBWith(t *testing.T, stmts string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "b.db")
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

func webkitTime(unix int64) int64 { return (unix + filetimeEpochDeltaSec) * 1_000_000 }

func browserEntries(t *testing.T, res object.Object, wantBrowser string) *object.Array {
	t.Helper()
	payload, errObj := unwrapPair(t, res)
	if errObj != nil {
		t.Fatalf("parse error: %s", errObj.Inspect())
	}
	h := payload.(*object.Hash)
	if got := hStr(t, h, "browser"); got != wantBrowser {
		t.Fatalf("browser = %q, want %q", got, wantBrowser)
	}
	return hashValueByKey(h, "entries").(*object.Array)
}

func TestBrowserHistoryChrome(t *testing.T) {
	const wantUnix = int64(1600000000)
	stmts := "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);" +
		"INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 5, " + itoa(webkitTime(wantUnix)) + ");"
	entries := browserEntries(t, BrowserHistory(stringObj(makeDBWith(t, stmts))), "chrome")
	if len(entries.Elements) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries.Elements))
	}
	e := entries.Elements[0].(*object.Hash)
	if hStr(t, e, "url") != "https://example.com" || hStr(t, e, "title") != "Example" || hInt(t, e, "visit_count") != 5 {
		t.Errorf("entry = %s", e.Inspect())
	}
	if hInt(t, e, "last_visit") != wantUnix {
		t.Errorf("last_visit = %d, want %d", hInt(t, e, "last_visit"), wantUnix)
	}
}

func TestBrowserHistoryFirefox(t *testing.T) {
	const wantUnix = int64(1600000000)
	stmts := "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);" +
		"INSERT INTO moz_places VALUES (1, 'https://ff.example', 'FF', 3, " + itoa(wantUnix*1_000_000) + ");"
	entries := browserEntries(t, BrowserHistory(stringObj(makeDBWith(t, stmts))), "firefox")
	e := entries.Elements[0].(*object.Hash)
	if hStr(t, e, "url") != "https://ff.example" || hInt(t, e, "last_visit") != wantUnix {
		t.Errorf("entry = %s", e.Inspect())
	}
}

func TestBrowserCookiesChrome(t *testing.T) {
	stmts := "CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER);" +
		"INSERT INTO cookies VALUES ('.example.com','sid','plainval', X'', '/', " + itoa(webkitTime(1700000000)) + ", 1, 0);" +
		"INSERT INTO cookies VALUES ('.example.com','enc','', X'DEADBEEF', '/', 0, 0, 1);"
	entries := browserEntries(t, BrowserCookies(stringObj(makeDBWith(t, stmts))), "chrome")
	if len(entries.Elements) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries.Elements))
	}
	e0 := entries.Elements[0].(*object.Hash)
	if hStr(t, e0, "value") != "plainval" || hBoolAt(t, e0, "encrypted") {
		t.Errorf("plain cookie wrong: %s", e0.Inspect())
	}
	if !hBoolAt(t, e0, "secure") || hBoolAt(t, e0, "http_only") {
		t.Errorf("plain cookie flags wrong: %s", e0.Inspect())
	}
	if hInt(t, e0, "expires") != 1700000000 {
		t.Errorf("expires = %d", hInt(t, e0, "expires"))
	}
	e1 := entries.Elements[1].(*object.Hash)
	if hStr(t, e1, "value") != "" || !hBoolAt(t, e1, "encrypted") {
		t.Errorf("encrypted cookie wrong: %s", e1.Inspect())
	}
}

func TestBrowserCookiesFirefox(t *testing.T) {
	stmts := "CREATE TABLE moz_cookies (host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, isSecure INTEGER, isHttpOnly INTEGER);" +
		"INSERT INTO moz_cookies VALUES ('.ff.example','ffsid','ffval','/', 1700000000, 1, 1);"
	entries := browserEntries(t, BrowserCookies(stringObj(makeDBWith(t, stmts))), "firefox")
	e := entries.Elements[0].(*object.Hash)
	if hStr(t, e, "value") != "ffval" || hInt(t, e, "expires") != 1700000000 {
		t.Errorf("ff cookie wrong: %s", e.Inspect())
	}
	if !hBoolAt(t, e, "secure") || !hBoolAt(t, e, "http_only") {
		t.Errorf("ff cookie flags wrong: %s", e.Inspect())
	}
}

func TestBrowserDownloadsChrome(t *testing.T) {
	stmts := "CREATE TABLE downloads (id INTEGER PRIMARY KEY, tab_url TEXT, target_path TEXT, total_bytes INTEGER, received_bytes INTEGER, start_time INTEGER, end_time INTEGER, state INTEGER, mime_type TEXT);" +
		"INSERT INTO downloads VALUES (1, 'https://dl.example/file.zip', 'C:\\Users\\x\\file.zip', 1000, 1000, " + itoa(webkitTime(1600000000)) + ", " + itoa(webkitTime(1600000005)) + ", 1, 'application/zip');"
	entries := browserEntries(t, BrowserDownloads(stringObj(makeDBWith(t, stmts))), "chrome")
	e := entries.Elements[0].(*object.Hash)
	if hStr(t, e, "url") != "https://dl.example/file.zip" || hStr(t, e, "target_path") != `C:\Users\x\file.zip` {
		t.Errorf("download url/path wrong: %s", e.Inspect())
	}
	if hInt(t, e, "bytes_total") != 1000 || hStr(t, e, "state") != "complete" {
		t.Errorf("download bytes/state wrong: %s", e.Inspect())
	}
	if hInt(t, e, "start_time") != 1600000000 {
		t.Errorf("start_time = %d", hInt(t, e, "start_time"))
	}
}

func TestBrowserDownloadsFirefox(t *testing.T) {
	stmts := "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT);" +
		"CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name TEXT);" +
		"CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content TEXT);" +
		"INSERT INTO moz_places VALUES (1, 'https://dl.ff/file.bin');" +
		"INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI');" +
		"INSERT INTO moz_annos VALUES (1, 1, 1, 'file:///home/x/file.bin');"
	entries := browserEntries(t, BrowserDownloads(stringObj(makeDBWith(t, stmts))), "firefox")
	if len(entries.Elements) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries.Elements))
	}
	e := entries.Elements[0].(*object.Hash)
	if hStr(t, e, "url") != "https://dl.ff/file.bin" || hStr(t, e, "target_path") != "file:///home/x/file.bin" {
		t.Errorf("ff download wrong: %s", e.Inspect())
	}
}

func TestBrowserUnrecognized(t *testing.T) {
	path := makeDBWith(t, "CREATE TABLE random (a INTEGER);")
	if _, e := unwrapPair(t, BrowserHistory(stringObj(path))); e == nil {
		t.Error("expected error for an unrecognized history database")
	}
	if _, e := unwrapPair(t, BrowserCookies(stringObj(path))); e == nil {
		t.Error("expected error for an unrecognized cookie database")
	}
}
