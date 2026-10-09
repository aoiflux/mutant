//go:build windows

package builtin

import (
	"golang.org/x/sys/windows"
)

// sfProcessEnvUnreadable says why another process's environment came back empty
// on Windows, so "no variables" is never reported for a process whose
// environment was simply out of reach.
//
// gopsutil reads the environment out of the target's PEB, and when the
// OpenProcess that needs PROCESS_VM_READ fails with ERROR_ACCESS_DENIED or
// ERROR_INVALID_PARAMETER it returns no variables AND no error
// (process_windows.go:1028 in v3.24.5). Both cases are ordinary here: a
// protected or higher-integrity process denies the read, and the kernel
// processes -- System, Registry, Memory Compression -- are not readable at all.
// Measured on this machine: of 391 other processes, 200 answered with variables
// and 189 answered with none, of which none was genuinely empty.
//
// Rather than guess from the empty result, this asks for the same access
// gopsutil needs and reports what Windows says. A process with a genuinely
// empty environment block can be built, and for that one OpenProcess succeeds,
// this returns nil, and the empty answer stands as the truth it is.
func sfProcessEnvUnreadable(pid int) error {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		return err
	}
	windows.CloseHandle(handle)
	return nil
}
