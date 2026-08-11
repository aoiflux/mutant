package builtin

import (
	"encoding/binary"
	"fmt"
	"os"
	"unicode/utf16"

	"mutant/object"
)

// PrefetchParse decodes a Windows Prefetch (.pf) file — evidence of program
// execution (run count, last-run timestamps, and the files/volumes referenced
// during the application's startup). It transparently handles the Win10/11
// MAM-compressed container (Xpress-Huffman) and the raw SCCA formats for
// Windows XP (v17), Vista/7 (v23), Win8.1 (v26), and Win10/11 (v30/v31).
//
// Returns {version, executable, prefetch_hash, run_count, run_times[],
// files_loaded[], file_count, volumes[], compressed} paired with an error.
func PrefetchParse(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("prefetch_parse: panic during parse: %v", r))
		}
	}()

	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg("prefetch_parse", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return resultAndError(nil, newError("prefetch_parse: %s", err.Error()))
	}

	compressed := false
	if len(data) >= 8 && string(data[0:3]) == "MAM" {
		compressed = true
		uncompressedSize := int(binary.LittleEndian.Uint32(data[4:8]))
		decomp, derr := xpressHuffmanDecompress(data[8:], uncompressedSize)
		if derr != nil {
			return resultAndError(nil, newError("prefetch_parse: decompress: %s", derr.Error()))
		}
		data = decomp
	}

	parsed, perr := parsePrefetch(data)
	if perr != nil {
		return resultAndError(nil, newError("prefetch_parse: %s", perr.Error()))
	}
	parsed["compressed"] = boolObj(compressed)
	return resultAndError(makeHashObject(parsed), nil)
}

// parsePrefetch decodes an uncompressed SCCA prefetch buffer.
func parsePrefetch(data []byte) (map[string]object.Object, error) {
	if len(data) < 84 {
		return nil, fmt.Errorf("prefetch too small (%d bytes)", len(data))
	}
	if string(data[4:8]) != "SCCA" {
		return nil, fmt.Errorf("not a prefetch file (missing SCCA signature)")
	}
	version := binary.LittleEndian.Uint32(data[0:4])

	exeName := decodeUTF16Z(data[0x10:0x4C])
	hash := binary.LittleEndian.Uint32(data[0x4C:0x50])

	// Run-time / run-count offsets are the only version-specific pieces; the
	// section-offset table (0x54..0x77) is shared across v17/v23/v26/v30.
	var runTimesOff, runTimesCount, runCountOff int
	switch version {
	case 17: // Windows XP / 2003
		runTimesOff, runTimesCount, runCountOff = 0x78, 1, 0x90
	case 23: // Windows Vista / 7
		runTimesOff, runTimesCount, runCountOff = 0x80, 1, 0x98
	case 26: // Windows 8.1
		runTimesOff, runTimesCount, runCountOff = 0x80, 8, 0xD0
	case 30, 31: // Windows 10 / 11
		runTimesOff, runTimesCount, runCountOff = 0x80, 8, 0xD0
	default:
		// Unknown version: still return the header fields we trust.
		runTimesOff, runTimesCount, runCountOff = 0, 0, 0
	}

	runTimes := make([]object.Object, 0, runTimesCount)
	for i := 0; i < runTimesCount; i++ {
		o := runTimesOff + i*8
		if o+8 > len(data) {
			break
		}
		if u := filetimeToUnix(binary.LittleEndian.Uint64(data[o : o+8])); u != 0 {
			runTimes = append(runTimes, stringObj(unixToISO(u)))
		}
	}
	runCount := int64(0)
	if runCountOff > 0 && runCountOff+4 <= len(data) {
		runCount = int64(binary.LittleEndian.Uint32(data[runCountOff : runCountOff+4]))
	}

	// Filename strings: array of null-terminated UTF-16LE full paths referenced
	// during startup. Section offset @0x64, size @0x68 (all versions).
	files := make([]object.Object, 0)
	fnOff := pfLE32(data, 0x64)
	fnSize := pfLE32(data, 0x68)
	if fnOff > 0 && fnSize > 0 && fnOff+fnSize <= len(data) {
		for _, s := range splitUTF16Z(data[fnOff : fnOff+fnSize]) {
			files = append(files, stringObj(s))
		}
	}

	// Volumes: device path, serial number, and creation time. Best-effort with
	// bounds checks — a malformed volume section never fails the whole parse.
	volumes := parsePrefetchVolumes(data, version)

	return map[string]object.Object{
		"version":       intObj(int64(version)),
		"executable":    stringObj(exeName),
		"prefetch_hash": stringObj(fmt.Sprintf("%08X", hash)),
		"run_count":     intObj(runCount),
		"run_times":     &object.Array{Elements: runTimes},
		"files_loaded":  &object.Array{Elements: files},
		"file_count":    intObj(int64(len(files))),
		"volumes":       &object.Array{Elements: volumes},
	}, nil
}

// parsePrefetchVolumes reads the volume-information section (offset @0x6C, count
// @0x70). Each entry's stride is version-dependent; every field access is
// bounds-checked so a bad entry is skipped rather than panicking.
func parsePrefetchVolumes(data []byte, version uint32) []object.Object {
	volumes := make([]object.Object, 0)
	volOff := pfLE32(data, 0x6C)
	volCount := pfLE32(data, 0x70)
	if volOff <= 0 || volCount <= 0 || volCount > 256 || volOff >= len(data) {
		return volumes
	}
	stride := 104 // v23
	if version >= 26 {
		stride = 96 // v26/v30/v31
	}
	for i := 0; i < volCount; i++ {
		base := volOff + i*stride
		if base+0x14 > len(data) {
			break
		}
		devPathOff := pfLE32(data, base+0x00)
		devPathChars := pfLE32(data, base+0x04)
		creation := filetimeToUnix(binary.LittleEndian.Uint64(data[base+0x08 : base+0x10]))
		serial := binary.LittleEndian.Uint32(data[base+0x10 : base+0x14])

		devPath := ""
		if devPathOff > 0 && devPathChars > 0 && devPathChars < 1024 {
			start := volOff + devPathOff
			end := start + devPathChars*2
			if start >= 0 && end <= len(data) && start < end {
				devPath = decodeUTF16Z(data[start:end])
			}
		}
		volumes = append(volumes, makeHashObject(map[string]object.Object{
			"device_path": stringObj(devPath),
			"serial":      stringObj(fmt.Sprintf("%08X", serial)),
			"created":     intObj(creation),
			"created_iso": stringObj(unixToISO(creation)),
		}))
	}
	return volumes
}

// ---------------------------------------------------------------------------
// Xpress-Huffman (MS-XCA LZ77+Huffman) decompressor — pure Go, no cgo.
// Validated byte-for-byte against ntdll RtlCompressBuffer/RtlDecompressBufferEx
// across compressible, incompressible, single- and multi-block inputs.
// ---------------------------------------------------------------------------

// maxPrefetchDecompressed caps the declared uncompressed size to guard against a
// crafted MAM header requesting an absurd allocation. Real prefetch files are a
// few MB at most.
const maxPrefetchDecompressed = 64 << 20

func xpressHuffmanDecompress(src []byte, outSize int) ([]byte, error) {
	if outSize < 0 || outSize > maxPrefetchDecompressed {
		return nil, fmt.Errorf("declared uncompressed size %d out of range", outSize)
	}
	dst := make([]byte, 0, outSize)
	inPos := 0
	for len(dst) < outSize {
		if inPos+256 > len(src) {
			return nil, fmt.Errorf("truncated Huffman table at offset %d", inPos)
		}
		var lengths [512]uint8
		for i := 0; i < 256; i++ {
			b := src[inPos+i]
			lengths[2*i] = b & 0x0F
			lengths[2*i+1] = b >> 4
		}
		table := buildXHTable(lengths[:])
		bs := newXHBitStream(src, inPos+256)

		blockEnd := len(dst) + 65536
		if blockEnd > outSize {
			blockEnd = outSize
		}
		for len(dst) < blockEnd {
			sym, ok := table.decode(bs)
			if !ok {
				return nil, fmt.Errorf("invalid Huffman code at output offset %d", len(dst))
			}
			if sym < 256 {
				dst = append(dst, byte(sym))
				continue
			}
			sym -= 256
			length := sym & 15
			offsetBits := sym >> 4
			// Extra length bytes come from the byte stream and MUST be read
			// before the offset bits (both advance the shared cursor).
			if length == 15 {
				b, bok := bs.byteAt()
				if !bok {
					return nil, fmt.Errorf("truncated match length at output offset %d", len(dst))
				}
				length = b + 15
				if b == 255 {
					v := int(xhU16(src, bs.index))
					bs.index += 2
					if v == 0 {
						v = int(xhU32(src, bs.index))
						bs.index += 4
					}
					length = v
				}
			}
			length += 3

			offset := (1 << uint(offsetBits)) + int(bs.lookup(offsetBits))
			bs.skip(offsetBits)

			matchPos := len(dst) - offset
			if offset <= 0 || matchPos < 0 {
				return nil, fmt.Errorf("invalid match offset %d at output offset %d", offset, len(dst))
			}
			if len(dst)+length > outSize {
				length = outSize - len(dst) // clamp corrupt/final overshoot
			}
			for i := 0; i < length; i++ {
				dst = append(dst, dst[matchPos+i])
			}
		}
		inPos = bs.index
	}
	return dst, nil
}

// xhBitStream reads the Xpress-Huffman bitstream: 16-bit little-endian words,
// bits consumed MSB-first, with a 32-bit lookahead. `index` is the shared
// forward cursor used both to refill the lookahead and to read raw length bytes.
type xhBitStream struct {
	src   []byte
	index int
	sym   uint32
	bits  int
}

func newXHBitStream(src []byte, pos int) *xhBitStream {
	bs := &xhBitStream{src: src, index: pos + 4}
	bs.sym = xhU16(src, pos)<<16 | xhU16(src, pos+2)
	bs.bits = 32
	return bs
}

func (bs *xhBitStream) lookup(n int) uint32 {
	if n <= 0 {
		return 0
	}
	return bs.sym >> (32 - uint(n))
}

func (bs *xhBitStream) skip(n int) {
	bs.sym = (bs.sym << uint(n)) & 0xFFFFFFFF
	bs.bits -= n
	if bs.bits < 16 {
		bs.sym |= xhU16(bs.src, bs.index) << (16 - uint(bs.bits))
		bs.index += 2
		bs.bits += 16
	}
}

func (bs *xhBitStream) byteAt() (int, bool) {
	if bs.index >= len(bs.src) {
		return 0, false
	}
	b := int(bs.src[bs.index])
	bs.index++
	return b, true
}

// xhTable is a canonical Huffman decode table for 512 symbols (0-255 literals,
// 256-511 length/offset match codes).
type xhTable struct {
	count  [16]int
	symbol [512]int
}

func buildXHTable(lengths []uint8) *xhTable {
	t := &xhTable{}
	for _, l := range lengths {
		t.count[l]++
	}
	t.count[0] = 0
	var offs [16]int
	for i := 1; i < 16; i++ {
		offs[i] = offs[i-1] + t.count[i-1]
	}
	for sym, l := range lengths {
		if l != 0 {
			t.symbol[offs[l]] = sym
			offs[l]++
		}
	}
	return t
}

// decode reads one canonical Huffman code (MSB-first) and returns its symbol.
func (t *xhTable) decode(bs *xhBitStream) (int, bool) {
	code, first, index := 0, 0, 0
	for l := 1; l <= 15; l++ {
		code |= int(bs.lookup(1))
		bs.skip(1)
		cnt := t.count[l]
		if code-first < cnt {
			return t.symbol[index+(code-first)], true
		}
		index += cnt
		first = (first + cnt) << 1
		code <<= 1
	}
	return 0, false
}

func xhU16(src []byte, i int) uint32 {
	if i < 0 || i+2 > len(src) {
		return 0
	}
	return uint32(src[i]) | uint32(src[i+1])<<8
}

func xhU32(src []byte, i int) uint32 {
	if i < 0 || i+4 > len(src) {
		return 0
	}
	return binary.LittleEndian.Uint32(src[i : i+4])
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

func pfLE32(data []byte, off int) int {
	if off < 0 || off+4 > len(data) {
		return 0
	}
	return int(binary.LittleEndian.Uint32(data[off : off+4]))
}

// decodeUTF16Z decodes UTF-16LE up to the first null character.
func decodeUTF16Z(b []byte) string {
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u16 = append(u16, c)
	}
	return string(utf16.Decode(u16))
}

// splitUTF16Z splits a buffer of consecutive null-terminated UTF-16LE strings.
func splitUTF16Z(b []byte) []string {
	out := make([]string, 0)
	cur := make([]uint16, 0, 32)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			if len(cur) > 0 {
				out = append(out, string(utf16.Decode(cur)))
				cur = cur[:0]
			}
			continue
		}
		cur = append(cur, c)
	}
	if len(cur) > 0 {
		out = append(out, string(utf16.Decode(cur)))
	}
	return out
}
