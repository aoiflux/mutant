package builtin

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"

	"mutant/object"
)

// sqliteMaxRows caps a single query's result set to guard against a runaway
// query exhausting memory; the result carries a `truncated` flag when hit.
const sqliteMaxRows = 1_000_000

// SqliteQuery runs a read-only SQL query against a SQLite database and returns
// the rows. The database (and any -wal/-shm sidecars) is copied to a temp file
// first, so the original is never modified or lock-contended — important for
// forensic databases that a running application may hold open. Pure-Go via
// modernc.org/sqlite (no cgo). An optional third argument binds query parameters.
// Returns {columns, row_count, truncated, rows:[{col: value}]} paired with an error.
func SqliteQuery(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("sqlite_query: panic during query: %v", r))
		}
	}()

	if len(args) < 2 || len(args) > 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}
	path, errObj := requireStringArg("sqlite_query", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	query, errObj := requireStringArg("sqlite_query", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	var params []any
	if len(args) == 3 {
		arr, ok := args[2].(*object.Array)
		if !ok {
			return resultAndError(nil, newError("argument 3 to `sqlite_query` must be ARRAY, got %s", args[2].Type()))
		}
		for _, el := range arr.Elements {
			params = append(params, objToSQLParam(el))
		}
	}

	columns, rows, truncated, err := sqliteQuery(path, query, params)
	if err != nil {
		return resultAndError(nil, newError("sqlite_query: %s", err.Error()))
	}

	colObjs := make([]object.Object, len(columns))
	for i, c := range columns {
		colObjs[i] = stringObj(c)
	}
	rowObjs := make([]object.Object, len(rows))
	for i, r := range rows {
		rowObjs[i] = makeHashObject(r)
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"columns":   &object.Array{Elements: colObjs},
		"row_count": intObj(int64(len(rows))),
		"truncated": boolObj(truncated),
		"rows":      &object.Array{Elements: rowObjs},
	}), nil)
}

// withSQLiteCopy copies the database (and any -wal/-shm sidecars) to a temp file,
// opens it, and invokes fn with the connection. The original is never touched, so
// a live/locked forensic database is safe to read. The temp copy is always
// removed. Shared by sqlite_query and the browser_* artifact parsers.
func withSQLiteCopy(path string, fn func(*sql.DB) error) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	tmpDir, err := os.MkdirTemp("", "mutant-sqlite-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	tmpDB := filepath.Join(tmpDir, "db.sqlite")
	if err := copyFileContents(path, tmpDB); err != nil {
		return err
	}
	// Bring along the WAL/SHM sidecars so committed-but-not-checkpointed data is
	// visible; SQLite replays them when the copy is opened.
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); err == nil {
			_ = copyFileContents(path+suffix, tmpDB+suffix)
		}
	}

	db, err := sql.Open("sqlite", tmpDB)
	if err != nil {
		return err
	}
	defer db.Close()
	return fn(db)
}

// sqliteQuery copies the database and runs one query against the copy, returning
// the column names and rows (each a column→value map).
func sqliteQuery(path, query string, params []any) ([]string, []map[string]object.Object, bool, error) {
	var columns []string
	var out []map[string]object.Object
	var truncated bool
	err := withSQLiteCopy(path, func(db *sql.DB) error {
		c, r, t, e := queryDB(db, query, params...)
		columns, out, truncated = c, r, t
		return e
	})
	return columns, out, truncated, err
}

// queryDB runs a query on an open connection and scans the rows.
func queryDB(db *sql.DB, query string, params ...any) ([]string, []map[string]object.Object, bool, error) {
	rows, err := db.Query(query, params...)
	if err != nil {
		return nil, nil, false, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, nil, false, err
	}

	out := make([]map[string]object.Object, 0)
	truncated := false
	for rows.Next() {
		if len(out) >= sqliteMaxRows {
			truncated = true
			break
		}
		cells := make([]any, len(columns))
		ptrs := make([]any, len(columns))
		for i := range cells {
			ptrs[i] = &cells[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, nil, false, err
		}
		row := make(map[string]object.Object, len(columns))
		for i, c := range columns {
			row[c] = sqlValueToObject(cells[i])
		}
		out = append(out, row)
	}
	return columns, out, truncated, rows.Err()
}

// sqliteTableExists reports whether a table is present in the opened database.
func sqliteTableExists(db *sql.DB, name string) bool {
	var n int
	err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n)
	return err == nil && n > 0
}

// rowStr / rowInt read a value out of a scanned row map with type coercion.
func rowStr(row map[string]object.Object, key string) string {
	if v, ok := row[key].(*object.String); ok {
		return v.Value
	}
	return ""
}

func rowInt(row map[string]object.Object, key string) int64 {
	switch v := row[key].(type) {
	case *object.Integer:
		return v.Value
	case *object.Float:
		return int64(v.Value)
	}
	return 0
}

func sqlValueToObject(v any) object.Object {
	switch x := v.(type) {
	case nil:
		return &object.Null{}
	case int64:
		return intObj(x)
	case float64:
		return floatObj(x)
	case bool:
		return boolObj(x)
	case string:
		return stringObj(x)
	case []byte:
		if utf8.Valid(x) {
			return stringObj(string(x))
		}
		return stringObj(hex.EncodeToString(x))
	case time.Time:
		return stringObj(x.UTC().Format(time.RFC3339))
	default:
		return stringObj(fmt.Sprintf("%v", x))
	}
}

func objToSQLParam(o object.Object) any {
	switch v := o.(type) {
	case *object.Integer:
		return v.Value
	case *object.Float:
		return v.Value
	case *object.String:
		return v.Value
	case *object.Boolean:
		return v.Value
	case *object.Null:
		return nil
	default:
		return o.Inspect()
	}
}

func copyFileContents(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
