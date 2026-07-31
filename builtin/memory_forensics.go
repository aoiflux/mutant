package builtin

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"

	"mutant/object"
)

func MemMap(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `mem_map` must be STRING, got %s", args[0].Type()))
	}

	data, err := os.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("mem_map: %s", err.Error()))
	}

	const chunkSize = 4096
	segments := make([]object.Object, 0)
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		segmentData := data[off:end]
		// A raw dump carries no page-protection metadata, so instead of fabricating
		// readable/writable/executable flags we report measurable per-segment
		// properties: Shannon entropy and the ratio of printable bytes. High
		// entropy suggests packed/encrypted/code regions; a high printable ratio
		// suggests text/strings.
		segments = append(segments, makeHashObject(map[string]object.Object{
			"offset":          intObj(int64(off)),
			"size":            intObj(int64(len(segmentData))),
			"entropy":         &object.Float{Value: shannonEntropy(segmentData)},
			"printable_ratio": &object.Float{Value: printableByteRatio(segmentData)},
		}))
	}

	return resultAndError(&object.Array{Elements: segments}, nil)
}

func MemRead(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `mem_read` must be STRING, got %s", args[0].Type()))
	}
	offsetObj, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `mem_read` must be INTEGER, got %s", args[1].Type()))
	}
	lengthObj, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `mem_read` must be INTEGER, got %s", args[2].Type()))
	}
	if offsetObj.Value < 0 || lengthObj.Value < 0 {
		return resultAndError(nil, newError("mem_read: offset and length must be >= 0"))
	}

	data, err := os.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("mem_read: %s", err.Error()))
	}

	start := int(offsetObj.Value)
	if start > len(data) {
		return resultAndError(nil, newError("mem_read: offset out of range"))
	}
	end := start + int(lengthObj.Value)
	if end > len(data) {
		end = len(data)
	}
	slice := data[start:end]

	return resultAndError(makeHashObject(map[string]object.Object{
		"offset": intObj(offsetObj.Value),
		"size":   intObj(int64(len(slice))),
		"hex":    stringObj(hex.EncodeToString(slice)),
	}), nil)
}

func MemScan(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `mem_scan` must be STRING, got %s", args[0].Type()))
	}
	patternObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `mem_scan` must be STRING, got %s", args[1].Type()))
	}

	data, err := os.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("mem_scan: %s", err.Error()))
	}
	needle := []byte(patternObj.Value)
	if len(needle) == 0 {
		return resultAndError(nil, newError("mem_scan: pattern must not be empty"))
	}

	offsets := make([]object.Object, 0)
	cursor := 0
	for {
		idx := bytes.Index(data[cursor:], needle)
		if idx < 0 {
			break
		}
		off := cursor + idx
		offsets = append(offsets, intObj(int64(off)))
		cursor = off + 1
		if cursor >= len(data) {
			break
		}
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"pattern": stringObj(patternObj.Value),
		"count":   intObj(int64(len(offsets))),
		"offsets": &object.Array{Elements: offsets},
	}), nil)
}

func MemStrings(args ...object.Object) object.Object {
	if len(args) != 1 && len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `mem_strings` must be STRING, got %s", args[0].Type()))
	}

	minLen := int64(4)
	if len(args) == 2 {
		minLenObj, ok := args[1].(*object.Integer)
		if !ok {
			return resultAndError(nil, newError("argument 2 to `mem_strings` must be INTEGER, got %s", args[1].Type()))
		}
		if minLenObj.Value < 1 {
			return resultAndError(nil, newError("mem_strings: min length must be >= 1"))
		}
		minLen = minLenObj.Value
	}

	data, err := os.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("mem_strings: %s", err.Error()))
	}

	stringsOut := extractPrintableStrings(data, int(minLen))
	elements := make([]object.Object, len(stringsOut))
	for i, s := range stringsOut {
		elements[i] = stringObj(s)
	}
	return resultAndError(&object.Array{Elements: elements}, nil)
}

func MemFindPE(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `mem_find_pe` must be STRING, got %s", args[0].Type()))
	}

	data, err := os.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("mem_find_pe: %s", err.Error()))
	}

	// Each MZ marker is a candidate; a real PE is confirmed by following the DOS
	// header's e_lfanew pointer (at +0x3C) to a "PE\0\0" signature.
	mzOffsets := carveOffsets(data, []byte{0x4d, 0x5a})
	headers := make([]object.Object, 0, len(mzOffsets))
	confirmed := 0
	for _, mz := range mzOffsets {
		peOffset, machine, ok := validatePEAt(data, mz)
		entry := map[string]object.Object{
			"mz_offset": intObj(int64(mz)),
			"confirmed": boolObj(ok),
		}
		if ok {
			confirmed++
			entry["pe_offset"] = intObj(int64(peOffset))
			entry["machine"] = stringObj(peMachineName(machine))
		}
		headers = append(headers, makeHashObject(entry))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"candidates": intObj(int64(len(mzOffsets))),
		"confirmed":  intObj(int64(confirmed)),
		"headers":    &object.Array{Elements: headers},
	}), nil)
}

// validatePEAt checks whether the MZ marker at mz is a real PE header by
// following e_lfanew (DOS header +0x3C) to a "PE\0\0" signature, returning the
// absolute PE-header offset and COFF machine type.
func validatePEAt(data []byte, mz int) (peOffset int, machine uint16, ok bool) {
	if mz+0x40 > len(data) {
		return 0, 0, false
	}
	eLfanew := int(binary.LittleEndian.Uint32(data[mz+0x3C : mz+0x40]))
	peAbs := mz + eLfanew
	if eLfanew <= 0 || peAbs+6 > len(data) || peAbs < mz {
		return 0, 0, false
	}
	if !(data[peAbs] == 'P' && data[peAbs+1] == 'E' && data[peAbs+2] == 0 && data[peAbs+3] == 0) {
		return 0, 0, false
	}
	return peAbs, binary.LittleEndian.Uint16(data[peAbs+4 : peAbs+6]), true
}

func peMachineName(m uint16) string {
	switch m {
	case 0x014c:
		return "i386"
	case 0x8664:
		return "amd64"
	case 0x01c0:
		return "arm"
	case 0xaa64:
		return "arm64"
	case 0x0200:
		return "ia64"
	default:
		return "unknown"
	}
}

func MemFindShellcode(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `mem_find_shellcode` must be STRING, got %s", args[0].Type()))
	}

	data, err := os.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("mem_find_shellcode: %s", err.Error()))
	}

	// Heuristic signatures for common x86 shellcode prefixes.
	signatures := [][]byte{
		{0x90, 0x90, 0x90},
		{0xfc, 0xe8},
		{0x31, 0xc0, 0x50, 0x68},
	}

	hits := make([]object.Object, 0)
	for _, sig := range signatures {
		offs := carveOffsets(data, sig)
		for _, off := range offs {
			hits = append(hits, makeHashObject(map[string]object.Object{
				"offset":    intObj(int64(off)),
				"signature": stringObj(strings.ToUpper(hex.EncodeToString(sig))),
			}))
		}
	}

	return resultAndError(&object.Array{Elements: hits}, nil)
}

// printableByteRatio returns the fraction (0–1) of bytes that are printable
// ASCII (including space, tab, CR, LF).
func printableByteRatio(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	printable := 0
	for _, b := range data {
		if (b >= 0x20 && b <= 0x7e) || b == '\t' || b == '\n' || b == '\r' {
			printable++
		}
	}
	return float64(printable) / float64(len(data))
}
