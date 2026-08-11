package builtin

import "bytes"

// memScanChunkSize bounds how much of a memory region is read/held at once.
const memScanChunkSize = 4 << 20 // 4 MiB

// scanBufferForPattern appends the absolute address (base+offset) of every
// occurrence of pattern in buf to matches. It returns true once maxMatches is
// reached (signalling the caller to stop early). Overlapping matches are found.
func scanBufferForPattern(buf []byte, base uint64, pattern []byte, matches *[]uint64, maxMatches int) bool {
	if len(pattern) == 0 || len(buf) < len(pattern) {
		return false
	}
	start := 0
	for start <= len(buf)-len(pattern) {
		idx := bytes.Index(buf[start:], pattern)
		if idx < 0 {
			break
		}
		*matches = append(*matches, base+uint64(start+idx))
		if maxMatches > 0 && len(*matches) >= maxMatches {
			return true
		}
		start += idx + 1
	}
	return false
}
