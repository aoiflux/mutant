//go:build windows

package builtin

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// sfScanSelfMemory scans this process's own committed, readable memory regions
// for pattern, enumerating regions with VirtualQuery and reading them with
// ReadProcessMemory against the current-process pseudo-handle.
func sfScanSelfMemory(pattern []byte, maxMatches int) ([]uint64, bool, error) {
	proc := windows.CurrentProcess()
	matches := make([]uint64, 0)
	overlap := uint64(len(pattern) - 1)

	var addr uintptr
	for {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
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
