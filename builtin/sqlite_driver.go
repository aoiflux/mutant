//go:build !wasm

package builtin

// Registers the pure-Go SQLite driver (modernc.org/sqlite) for the sqlite_query
// and browser_* builtins on every target except wasm. modernc.org/sqlite pulls in
// modernc.org/libc, which has no js/wasm build, so it is omitted from the browser
// WASM REPL; there, SQLite-backed builtins fail with an honest runtime error.
import _ "modernc.org/sqlite"
