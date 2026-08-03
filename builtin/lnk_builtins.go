package builtin

import (
	"encoding/binary"
	"os"
	"time"
	"unicode/utf16"

	"mutant/object"
)

// lnkFlagNames maps LinkFlags bits (MS-SHLLINK 2.1.1) to names, low bits first.
var lnkFlagNames = []struct {
	bit  uint32
	name string
}{
	{0x00000001, "HasLinkTargetIDList"},
	{0x00000002, "HasLinkInfo"},
	{0x00000004, "HasName"},
	{0x00000008, "HasRelativePath"},
	{0x00000010, "HasWorkingDir"},
	{0x00000020, "HasArguments"},
	{0x00000040, "HasIconLocation"},
	{0x00000080, "IsUnicode"},
	{0x00000100, "ForceNoLinkInfo"},
	{0x00000200, "HasExpString"},
	{0x00000400, "RunInSeparateProcess"},
	{0x00002000, "HasDarwinID"},
	{0x00004000, "RunAsUser"},
	{0x00008000, "HasExpIcon"},
}

// LnkParse parses a Windows shell link (.lnk) file, extracting the header
// (attributes, MAC timestamps as FILETIME), decoded LinkFlags, the LinkInfo local
// base path (target), and the StringData fields (name, relative path, working dir,
// arguments, icon location). Pure-Go; panic-recovered against malformed input.
func LnkParse(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("lnk_parse: panic during parse: %v", r))
		}
	}()

	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg("lnk_parse", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return resultAndError(nil, newError("lnk_parse: %s", err.Error()))
	}
	if len(data) < 76 || binary.LittleEndian.Uint32(data[0:4]) != 0x0000004C {
		return resultAndError(nil, newError("lnk_parse: not a shell link (bad header)"))
	}

	flags := binary.LittleEndian.Uint32(data[20:24])
	fileAttr := binary.LittleEndian.Uint32(data[24:28])
	creation := filetimeToUnix(binary.LittleEndian.Uint64(data[28:36]))
	access := filetimeToUnix(binary.LittleEndian.Uint64(data[36:44]))
	write := filetimeToUnix(binary.LittleEndian.Uint64(data[44:52]))
	fileSize := binary.LittleEndian.Uint32(data[52:56])
	iconIndex := int32(binary.LittleEndian.Uint32(data[56:60]))
	showCmd := binary.LittleEndian.Uint32(data[60:64])
	isUnicode := flags&0x80 != 0

	off := 76
	if flags&0x01 != 0 && off+2 <= len(data) { // HasLinkTargetIDList — skip it
		idListSize := int(binary.LittleEndian.Uint16(data[off : off+2]))
		off += 2 + idListSize
	}

	localBasePath := ""
	if flags&0x02 != 0 && off < len(data) { // HasLinkInfo
		localBasePath, off = parseLnkLinkInfo(data, off)
	}

	name, relPath, workDir, arguments, iconLoc := "", "", "", "", ""
	readStr := func() string {
		s, next := readLnkStringData(data, off, isUnicode)
		off = next
		return s
	}
	if flags&0x04 != 0 {
		name = readStr()
	}
	if flags&0x08 != 0 {
		relPath = readStr()
	}
	if flags&0x10 != 0 {
		workDir = readStr()
	}
	if flags&0x20 != 0 {
		arguments = readStr()
	}
	if flags&0x40 != 0 {
		iconLoc = readStr()
	}

	decoded := make([]object.Object, 0)
	for _, f := range lnkFlagNames {
		if flags&f.bit != 0 {
			decoded = append(decoded, stringObj(f.name))
		}
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"link_flags":         intObj(int64(flags)),
		"link_flags_decoded": &object.Array{Elements: decoded},
		"file_attributes":    intObj(int64(fileAttr)),
		"creation_time":      intObj(creation),
		"access_time":        intObj(access),
		"write_time":         intObj(write),
		"creation_iso":       stringObj(unixToISO(creation)),
		"write_iso":          stringObj(unixToISO(write)),
		"file_size":          intObj(int64(fileSize)),
		"icon_index":         intObj(int64(iconIndex)),
		"show_command":       intObj(int64(showCmd)),
		"is_unicode":         boolObj(isUnicode),
		"local_base_path":    stringObj(localBasePath),
		"name":               stringObj(name),
		"relative_path":      stringObj(relPath),
		"working_dir":        stringObj(workDir),
		"arguments":          stringObj(arguments),
		"icon_location":      stringObj(iconLoc),
	}), nil)
}

func filetimeToUnix(ft uint64) int64 {
	if ft == 0 {
		return 0
	}
	return int64(ft/10_000_000) - filetimeEpochDeltaSec
}

func unixToISO(unix int64) string {
	if unix == 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

// parseLnkLinkInfo returns the LinkInfo LocalBasePath (target) and the offset just
// past the LinkInfo block.
func parseLnkLinkInfo(data []byte, start int) (string, int) {
	if start+16 > len(data) {
		return "", len(data)
	}
	linkInfoSize := int(binary.LittleEndian.Uint32(data[start : start+4]))
	end := start + linkInfoSize
	if end > len(data) || end < start {
		end = len(data)
	}
	linkInfoFlags := binary.LittleEndian.Uint32(data[start+8 : start+12])
	localBasePath := ""
	if linkInfoFlags&0x01 != 0 { // VolumeIDAndLocalBasePath
		lbpOffset := int(binary.LittleEndian.Uint32(data[start+16 : start+20]))
		abs := start + lbpOffset
		if abs >= 0 && abs < end {
			localBasePath = readCString(data[:end], abs)
		}
	}
	return localBasePath, end
}

// readLnkStringData reads a StringData structure (2-byte character count followed
// by the string) and returns the string and the next offset.
func readLnkStringData(data []byte, off int, unicode bool) (string, int) {
	if off+2 > len(data) {
		return "", len(data)
	}
	count := int(binary.LittleEndian.Uint16(data[off : off+2]))
	off += 2
	if unicode {
		byteLen := count * 2
		if off+byteLen > len(data) {
			byteLen = len(data) - off
			byteLen -= byteLen % 2
		}
		return decodeUTF16LE(data[off : off+byteLen]), off + byteLen
	}
	byteLen := count
	if off+byteLen > len(data) {
		byteLen = len(data) - off
	}
	return string(data[off : off+byteLen]), off + byteLen
}

func decodeUTF16LE(b []byte) string {
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16))
}

func readCString(data []byte, start int) string {
	for i := start; i < len(data); i++ {
		if data[i] == 0 {
			return string(data[start:i])
		}
	}
	return string(data[start:])
}
