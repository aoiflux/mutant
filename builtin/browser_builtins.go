package builtin

import (
	"database/sql"
	"fmt"

	"mutant/object"
)

// Browser artifact parsers over Chromium (Chrome/Edge/Brave) and Firefox SQLite
// databases, built on the read-only copy-and-query SQLite helpers. Each parser
// auto-detects the schema by table presence and normalizes timestamps to unix.
//
// Timestamp bases:
//   - Chromium: microseconds since 1601-01-01 (WebKit/"Chrome" epoch).
//   - Firefox visit/creation times: microseconds since the Unix epoch.
//   - Firefox cookie expiry: whole Unix seconds.

func webkitMicrosToUnix(us int64) int64 {
	if us <= 0 {
		return 0
	}
	return us/1_000_000 - filetimeEpochDeltaSec
}

func microsToUnix(us int64) int64 {
	if us <= 0 {
		return 0
	}
	return us / 1_000_000
}

// BrowserHistory parses a Chromium History or Firefox places.sqlite database into
// normalized visit entries {url, title, visit_count, last_visit, last_visit_iso,
// browser}. Returns {browser, count, entries} paired with an error.
func BrowserHistory(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("browser_history: panic during parse: %v", r))
		}
	}()

	path, errObj := browserArg("browser_history", args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	var entries []object.Object
	browser := ""
	err := withSQLiteCopy(path, func(db *sql.DB) error {
		switch {
		case sqliteTableExists(db, "urls"): // Chromium
			browser = "chrome"
			_, rows, _, e := queryDB(db, `SELECT url, title, visit_count, last_visit_time FROM urls`)
			if e != nil {
				return e
			}
			for _, r := range rows {
				entries = append(entries, historyEntry(r, "url", "title", "visit_count", webkitMicrosToUnix(rowInt(r, "last_visit_time")), "chrome"))
			}
		case sqliteTableExists(db, "moz_places"): // Firefox
			browser = "firefox"
			_, rows, _, e := queryDB(db, `SELECT url, title, visit_count, last_visit_date FROM moz_places WHERE url IS NOT NULL`)
			if e != nil {
				return e
			}
			for _, r := range rows {
				entries = append(entries, historyEntry(r, "url", "title", "visit_count", microsToUnix(rowInt(r, "last_visit_date")), "firefox"))
			}
		default:
			return fmt.Errorf("unrecognized history database (no 'urls' or 'moz_places' table)")
		}
		return nil
	})
	if err != nil {
		return resultAndError(nil, newError("browser_history: %s", err.Error()))
	}
	return resultAndError(browserResult(browser, entries), nil)
}

func historyEntry(r map[string]object.Object, urlKey, titleKey, countKey string, lastVisit int64, browser string) object.Object {
	return makeHashObject(map[string]object.Object{
		"url":            stringObj(rowStr(r, urlKey)),
		"title":          stringObj(rowStr(r, titleKey)),
		"visit_count":    intObj(rowInt(r, countKey)),
		"last_visit":     intObj(lastVisit),
		"last_visit_iso": stringObj(unixToISO(lastVisit)),
		"browser":        stringObj(browser),
	})
}

// BrowserCookies parses a Chromium Cookies or Firefox cookies.sqlite database.
// Chromium cookie values are OS-encrypted (DPAPI / Keychain / libsecret); when a
// row has only an encrypted value it is reported with encrypted=true and an empty
// value (decryption needs the OS keys, out of scope). Returns {browser, count,
// entries:[{host, name, value, path, expires, expires_iso, secure, http_only,
// encrypted, browser}]}.
func BrowserCookies(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("browser_cookies: panic during parse: %v", r))
		}
	}()

	path, errObj := browserArg("browser_cookies", args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	var entries []object.Object
	browser := ""
	err := withSQLiteCopy(path, func(db *sql.DB) error {
		switch {
		case sqliteTableExists(db, "cookies"): // Chromium
			browser = "chrome"
			_, rows, _, e := queryDB(db, `SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies`)
			if e != nil {
				return e
			}
			for _, r := range rows {
				value := rowStr(r, "value")
				encrypted := value == "" && rowStr(r, "encrypted_value") != ""
				entries = append(entries, cookieEntry(rowStr(r, "host_key"), rowStr(r, "name"), value, rowStr(r, "path"),
					webkitMicrosToUnix(rowInt(r, "expires_utc")), rowInt(r, "is_secure") != 0, rowInt(r, "is_httponly") != 0, encrypted, "chrome"))
			}
		case sqliteTableExists(db, "moz_cookies"): // Firefox
			browser = "firefox"
			_, rows, _, e := queryDB(db, `SELECT host, name, value, path, expiry, isSecure, isHttpOnly FROM moz_cookies`)
			if e != nil {
				return e
			}
			for _, r := range rows {
				entries = append(entries, cookieEntry(rowStr(r, "host"), rowStr(r, "name"), rowStr(r, "value"), rowStr(r, "path"),
					rowInt(r, "expiry"), rowInt(r, "isSecure") != 0, rowInt(r, "isHttpOnly") != 0, false, "firefox"))
			}
		default:
			return fmt.Errorf("unrecognized cookie database (no 'cookies' or 'moz_cookies' table)")
		}
		return nil
	})
	if err != nil {
		return resultAndError(nil, newError("browser_cookies: %s", err.Error()))
	}
	return resultAndError(browserResult(browser, entries), nil)
}

func cookieEntry(host, name, value, path string, expires int64, secure, httpOnly, encrypted bool, browser string) object.Object {
	return makeHashObject(map[string]object.Object{
		"host":        stringObj(host),
		"name":        stringObj(name),
		"value":       stringObj(value),
		"path":        stringObj(path),
		"expires":     intObj(expires),
		"expires_iso": stringObj(unixToISO(expires)),
		"secure":      boolObj(secure),
		"http_only":   boolObj(httpOnly),
		"encrypted":   boolObj(encrypted),
		"browser":     stringObj(browser),
	})
}

var chromeDownloadStates = map[int64]string{0: "in_progress", 1: "complete", 2: "cancelled", 3: "interrupted"}

// BrowserDownloads parses a Chromium History (downloads table) or Firefox
// places.sqlite (moz_annos) database into normalized download records. Firefox
// support is best-effort (the destination file URI annotation). Returns
// {browser, count, entries:[{url, target_path, bytes_total, bytes_received,
// start_time, end_time, state, mime_type, browser}]}.
func BrowserDownloads(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("browser_downloads: panic during parse: %v", r))
		}
	}()

	path, errObj := browserArg("browser_downloads", args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	var entries []object.Object
	browser := ""
	err := withSQLiteCopy(path, func(db *sql.DB) error {
		switch {
		case sqliteTableExists(db, "downloads"): // Chromium
			browser = "chrome"
			_, rows, _, e := queryDB(db, `SELECT tab_url, target_path, total_bytes, received_bytes, start_time, end_time, state, mime_type FROM downloads`)
			if e != nil {
				return e
			}
			for _, r := range rows {
				state := chromeDownloadStates[rowInt(r, "state")]
				if state == "" {
					state = "unknown"
				}
				entries = append(entries, makeHashObject(map[string]object.Object{
					"url":            stringObj(rowStr(r, "tab_url")),
					"target_path":    stringObj(rowStr(r, "target_path")),
					"bytes_total":    intObj(rowInt(r, "total_bytes")),
					"bytes_received": intObj(rowInt(r, "received_bytes")),
					"start_time":     intObj(webkitMicrosToUnix(rowInt(r, "start_time"))),
					"end_time":       intObj(webkitMicrosToUnix(rowInt(r, "end_time"))),
					"state":          stringObj(state),
					"mime_type":      stringObj(rowStr(r, "mime_type")),
					"browser":        stringObj("chrome"),
				}))
			}
		case sqliteTableExists(db, "moz_annos"): // Firefox (best-effort)
			browser = "firefox"
			_, rows, _, e := queryDB(db, `
				SELECT p.url AS source_url, a.content AS target
				FROM moz_annos a
				JOIN moz_places p ON p.id = a.place_id
				JOIN moz_anno_attributes aa ON aa.id = a.anno_attribute_id
				WHERE aa.name = 'downloads/destinationFileURI'`)
			if e != nil {
				return e
			}
			for _, r := range rows {
				entries = append(entries, makeHashObject(map[string]object.Object{
					"url":            stringObj(rowStr(r, "source_url")),
					"target_path":    stringObj(rowStr(r, "target")),
					"bytes_total":    intObj(0),
					"bytes_received": intObj(0),
					"start_time":     intObj(0),
					"end_time":       intObj(0),
					"state":          stringObj(""),
					"mime_type":      stringObj(""),
					"browser":        stringObj("firefox"),
				}))
			}
		default:
			return fmt.Errorf("unrecognized download database (no 'downloads' or 'moz_annos' table)")
		}
		return nil
	})
	if err != nil {
		return resultAndError(nil, newError("browser_downloads: %s", err.Error()))
	}
	return resultAndError(browserResult(browser, entries), nil)
}

// browserArg validates the single path argument shared by the browser_* builtins.
func browserArg(op string, args []object.Object) (string, *object.Error) {
	if len(args) != 1 {
		return "", newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	return requireStringArg(op, args[0], 1)
}

func browserResult(browser string, entries []object.Object) object.Object {
	if entries == nil {
		entries = []object.Object{}
	}
	return makeHashObject(map[string]object.Object{
		"browser": stringObj(browser),
		"count":   intObj(int64(len(entries))),
		"entries": &object.Array{Elements: entries},
	})
}
