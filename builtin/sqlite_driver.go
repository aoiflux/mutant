//go:build !wasm

package builtin

// Registers the pure-Go SQLite driver (modernc.org/sqlite) for the sqlite_query
// and browser_* builtins on every target except wasm. modernc.org/sqlite pulls in
// modernc.org/libc, which has no js/wasm build, so it is omitted from the browser
// WASM REPL; there, SQLite-backed builtins fail with an honest runtime error.
import (
	"database/sql"
	"fmt"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// confineSQLiteConn stops conn reaching any database file but the one it was
// opened on. ATTACH is how SQL names another file, and VACUUM INTO attaches its
// output the same way, so a limit of zero attached databases refuses both. A
// limit set through sqlite3_limit cannot be raised again from SQL, which is
// what makes it a boundary and PRAGMA query_only only a courtesy.
func confineSQLiteConn(conn *sql.Conn) error {
	if _, err := sqlite.Limit(conn, sqlite3.SQLITE_LIMIT_ATTACHED, 0); err != nil {
		return err
	}
	now, err := sqlite.Limit(conn, sqlite3.SQLITE_LIMIT_ATTACHED, -1)
	if err != nil {
		return err
	}
	if now != 0 {
		return fmt.Errorf("the SQLite connection kept an attach limit of %d after it was set to 0", now)
	}
	return nil
}
