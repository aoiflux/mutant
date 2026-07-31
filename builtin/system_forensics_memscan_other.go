//go:build !linux && !windows

package builtin

import (
	"fmt"
	"runtime"
)

// sfScanSelfMemory is unavailable on platforms without a pure-Go region walker
// (e.g. macOS/BSD, where enumerating regions needs mach task APIs). It fails
// honestly rather than returning a fake result.
func sfScanSelfMemory(_ []byte, _ int) ([]uint64, bool, error) {
	return nil, false, fmt.Errorf("self memory scan not supported on %s", runtime.GOOS)
}
