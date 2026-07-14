package builtin

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"regexp"
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
		segments = append(segments, makeHashObject(map[string]object.Object{
			"offset":     intObj(int64(off)),
			"size":       intObj(int64(len(segmentData))),
			"readable":   boolObj(true),
			"writable":   boolObj(false),
			"executable": boolObj(likelyExecutableChunk(segmentData)),
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

	offsets := carveOffsets(data, []byte{0x4d, 0x5a})
	elements := make([]object.Object, len(offsets))
	for i, off := range offsets {
		elements[i] = intObj(int64(off))
	}
	return resultAndError(&object.Array{Elements: elements}, nil)
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

func likelyExecutableChunk(chunk []byte) bool {
	if len(chunk) == 0 {
		return false
	}
	if bytes.Contains(chunk, []byte{0x4d, 0x5a}) || bytes.Contains(chunk, []byte{0x7f, 0x45, 0x4c, 0x46}) {
		return true
	}
	re := regexp.MustCompile(`[\x55\x8B\xE5\xE8\xE9\xC3]`)
	return re.Match(chunk)
}

func MemMapLiveProcess(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	_, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `mem_map_live` must be INTEGER pid, got %s", args[0].Type()))
	}
	return resultAndError(nil, newError("mem_map_live unsupported: privileged live process memory access is not enabled"))
}

func memLines(data []byte) []string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lines := make([]string, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}
