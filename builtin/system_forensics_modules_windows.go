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
//
// Pid 0 is refused here. CreateToolhelp32Snapshot documents th32ProcessID 0 as
// meaning the current process, so process_modules(0) -- asked about the System
// Idle Process, which has no modules and which process_list returns first,
// because the list is sorted ascending -- came back with Mutant's own fourteen
// DLLs, its own image among them. A script walking process_list and recording
// each process's modules therefore filed the examining tool's libraries under
// pid 0 in its report. The refusal is at this API rather than in the shared pid
// validation because 0 is a pid the other builtins answer for legitimately, and
// narrowing the range they share would refuse it everywhere.
func sfProcessModulePaths(pid int) ([]string, error) {
	if pid == 0 {
		return nil, fmt.Errorf(
			"pid 0 is the System Idle Process and has no modules; " +
				"Toolhelp32 reads a process id of 0 as the calling process")
	}

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
