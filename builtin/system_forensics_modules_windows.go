//go:build windows

package builtin

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sfProcessModulePaths enumerates the loaded modules (the main image plus every
// loaded DLL) of a process on Windows using a Toolhelp32 module snapshot. This
// covers the gap left by gopsutil, which does not expose memory maps on Windows.
// Enumerating another process's modules may require elevation; failures surface
// as an honest error rather than an empty result.
func sfProcessModulePaths(pid int) ([]string, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(
		windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("module snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ModuleEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Module32First(snapshot, &entry); err != nil {
		return nil, fmt.Errorf("module enumerate: %w", err)
	}

	mods := make([]string, 0, 64)
	for {
		if path := windows.UTF16ToString(entry.ExePath[:]); path != "" {
			mods = append(mods, path)
		}
		if err := windows.Module32Next(snapshot, &entry); err != nil {
			// Any error (notably ERROR_NO_MORE_FILES) ends the enumeration.
			break
		}
	}
	return mods, nil
}
