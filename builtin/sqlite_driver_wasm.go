//go:build wasm

package builtin

import (
	"database/sql"
	"errors"
)

// confineSQLiteConn has nothing to confine on wasm, where no SQLite driver is
// registered and sql.Open has already failed; it refuses rather than pretend.
func confineSQLiteConn(*sql.Conn) error {
	return errors.New("SQLite is not available in this build")
}
