//go:build windows

package builtin

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sfScanProcessMemory scans a process's committed, readable memory regions for
// pattern, enumerating regions with VirtualQueryEx and reading them with
// ReadProcessMemory.
//
// For another process this opens a handle with PROCESS_QUERY_INFORMATION and
// PROCESS_VM_READ, which is what both calls need and no more; a protected or
// higher-integrity target refuses that open and the refusal is returned as it
// came. For this process the current-process pseudo-handle is used, and the
// caller is responsible for knowing that a self-scan cannot tell a finding from
// its own query -- ProcessMemoryScan refuses one for that reason.
func sfScanProcessMemory(pid int, pattern []byte, maxMatches int) ([]uint64, bool, error) {
	proc := windows.CurrentProcess()
	if pid != os.Getpid() {
		handle, err := windows.OpenProcess(
			windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
		if err != nil {
			return nil, false, fmt.Errorf("open process %d: %w", pid, err)
		}
		defer windows.CloseHandle(handle)
		proc = handle
	}

	matches := make([]uint64, 0)
	overlap := uint64(len(pattern) - 1)

	var addr uintptr
	for {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(proc, addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break // walked past the top of the address space
		}
		if mbi.RegionSize == 0 {
			break
		}

		readable := mbi.State == windows.MEM_COMMIT &&
			mbi.Protect != windows.PAGE_NOACCESS &&
			mbi.Protect&windows.PAGE_GUARD == 0
		if readable {
			base := uint64(mbi.BaseAddress)
			regionEnd := base + uint64(mbi.RegionSize)
			for off := base; off < regionEnd; {
				remaining := regionEnd - off
				chunk := uint64(memScanChunkSize)
				if chunk > remaining {
					chunk = remaining
				}
				buf := make([]byte, chunk)
				var read uintptr
				err := windows.ReadProcessMemory(proc, uintptr(off), &buf[0], uintptr(chunk), &read)
				if err == nil && read > 0 {
					if scanBufferForPattern(buf[:read], off, pattern, &matches, maxMatches) {
						return matches, true, nil
					}
				}
				if err != nil || chunk >= remaining {
					break
				}
				step := chunk - overlap
				if step == 0 {
					step = chunk
				}
				off += step
			}
		}

		next := uintptr(uint64(mbi.BaseAddress) + uint64(mbi.RegionSize))
		if next <= addr {
			break // guard against wraparound / no progress
		}
		addr = next
	}
	return matches, false, nil
}
