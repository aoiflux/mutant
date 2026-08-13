//go:build linux

package builtin

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// sfScanSelfMemory scans this process's own readable memory regions for pattern,
// reading /proc/self/maps for the region list and /proc/self/mem for the bytes.
func sfScanSelfMemory(pattern []byte, maxMatches int) ([]uint64, bool, error) {
	mapsFile, err := os.Open("/proc/self/maps")
	if err != nil {
		return nil, false, err
	}
	defer mapsFile.Close()

	mem, err := os.Open("/proc/self/mem")
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
