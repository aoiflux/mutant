//go:build !linux && !windows

package builtin

import (
	"fmt"
	"runtime"
)

// sfProcessModulePaths is not available off Linux via the current backend:
// gopsutil does not expose per-process memory maps on these platforms (Windows
// would require Toolhelp32/EnumProcessModules). It fails honestly rather than
// returning an empty result that would read as "no modules loaded".
func sfProcessModulePaths(_ int) ([]string, error) {
	return nil, fmt.Errorf("module enumeration not available on %s via the current backend", runtime.GOOS)
}
