//go:build linux

package builtin

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// sfScanProcessMemory scans a process's readable memory regions for pattern,
// reading /proc/<pid>/maps for the region list and /proc/<pid>/mem for the
// bytes.
//
// Reading another process's memory needs ptrace access to it, so on a host with
// the usual yama setting an unprivileged caller reaches its own descendants and
// nothing else. That arrives as the open error, which is returned as it came
// rather than reported as a scan that found nothing.
func sfScanProcessMemory(pid int, pattern []byte, maxMatches int) ([]uint64, bool, error) {
	dir := "/proc/self"
	if pid != os.Getpid() {
		dir = "/proc/" + strconv.Itoa(pid)
	}

	mapsFile, err := os.Open(dir + "/maps")
	if err != nil {
		return nil, false, err
	}
	defer mapsFile.Close()

	mem, err := os.Open(dir + "/mem")
	if err != nil {
		return nil, false, err
	}
	defer mem.Close()

	matches := make([]uint64, 0)
	overlap := uint64(len(pattern) - 1)
	scanner := bufio.NewScanner(mapsFile)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || len(fields[1]) < 1 || fields[1][0] != 'r' {
			continue // readable regions only
		}
		bounds := strings.SplitN(fields[0], "-", 2)
		if len(bounds) != 2 {
			continue
		}
		start, err1 := strconv.ParseUint(bounds[0], 16, 64)
		end, err2 := strconv.ParseUint(bounds[1], 16, 64)
		if err1 != nil || err2 != nil || end <= start {
			continue
		}

		for off := start; off < end; {
			remaining := end - off
			chunk := uint64(memScanChunkSize)
			if chunk > remaining {
				chunk = remaining
			}
			buf := make([]byte, chunk)
			n, rerr := mem.ReadAt(buf, int64(off))
			if n > 0 {
				if scanBufferForPattern(buf[:n], off, pattern, &matches, maxMatches) {
					return matches, true, nil
				}
			}
			if rerr != nil || chunk >= remaining {
				break // region ended or became unreadable
			}
			step := chunk - overlap
			if step == 0 {
				step = chunk
			}
			off += step
		}
	}
	return matches, false, nil
}
