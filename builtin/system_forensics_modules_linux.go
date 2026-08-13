//go:build linux

package builtin

import (
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

// sfProcessModulePaths returns the file-backed loaded modules for a pid by
// reading its memory maps (via gopsutil, backed by /proc/<pid>/maps on Linux).
func sfProcessModulePaths(pid int) ([]string, error) {
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return nil, err
	}

	maps, err := proc.MemoryMaps(false)
	if err != nil {
		return nil, err
	}

	mods := make([]string, 0)
	if maps != nil {
		for _, m := range *maps {
			if sfIsFileBackedPath(m.Path) {
				mods = append(mods, m.Path)
			}
		}
	}
	return mods, nil
}

// sfIsFileBackedPath reports whether a memory-map path refers to a real file on
// disk (a loaded module) rather than an anonymous or pseudo mapping such as
// "[heap]" or "[stack]".
func sfIsFileBackedPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "[") {
		return false
	}
	return strings.ContainsAny(p, "/\\")
}
