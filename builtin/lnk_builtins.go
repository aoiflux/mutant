package builtin

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"
	"unicode/utf16"

	"mutant/object"
)

// lnkFlagNames maps LinkFlags bits to names, low bits first. The bits, the
// names and this order are MS-SHLLINK 2.1.1, which defines twenty-seven of the
// thirty-two and reserves Unused1 and Unused2 by name. The two reserved bits
// are decoded like the rest: a reserved bit that is set says something about
// the file that produced the link, and leaving it out would make
// link_flags_decoded a selection from link_flags rather than an account of it.
//
// Bits 27 to 31 have no name in the specification. decodeLnkFlags reports each
// one it finds set as an unnamed bit rather than dropping it.
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
	{0x00000800, "Unused1"},
	{0x00001000, "HasDarwinID"},
	{0x00002000, "RunAsUser"},
	{0x00004000, "HasExpIcon"},
	{0x00008000, "NoPidlAlias"},
	{0x00010000, "Unused2"},
	{0x00020000, "RunWithShimLayer"},
	{0x00040000, "ForceNoLinkTrack"},
	{0x00080000, "EnableTargetMetadata"},
	{0x00100000, "DisableLinkPathTracking"},
	{0x00200000, "DisableKnownFolderTracking"},
	{0x00400000, "DisableKnownFolderAlias"},
	{0x00800000, "AllowLinkToLink"},
	{0x01000000, "UnaliasOnSave"},
	{0x02000000, "PreferEnvironmentPath"},
	{0x04000000, "KeepLocalIDListForUNCTarget"},
}

// lnkNamedFlagMask is every bit lnkFlagNames accounts for, so a bit outside it
// can be reported rather than passed over. It is derived in init rather than
// written, because a mask written beside a table is a second place to forget.
var lnkNamedFlagMask uint32

func init() {
	for _, f := range lnkFlagNames {
		lnkNamedFlagMask |= f.bit
	}
}

// decodeLnkFlags names every set bit of a LinkFlags word. A bit the
// specification does not name is reported as "Bit<n>" instead of being
// dropped: link_flags is in the result beside this list, and a list that
// quietly accounts for less than the number it sits next to is the defect this
// function was rewritten to fix.
func decodeLnkFlags(flags uint32) []object.Object {
	decoded := make([]object.Object, 0)
	for _, f := range lnkFlagNames {
		if flags&f.bit != 0 {
			decoded = append(decoded, stringObj(f.name))
		}
	}
	for bit := 27; bit < 32; bit++ {
		if mask := uint32(1) << uint(bit); flags&mask != 0 && lnkNamedFlagMask&mask == 0 {
			decoded = append(decoded, stringObj(fmt.Sprintf("Bit%d", bit)))
		}
	}
	return decoded
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
	path, errObj := requireStringArg(BuiltinNameLnkParse, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return resultAndError(nil, newError("lnk_parse: %s", err.Error()))
	}
	m, _, perr := parseLnkFields(data)
	if perr != nil {
		return resultAndError(nil, newError("lnk_parse: %s", perr.Error()))
	}
	return resultAndError(makeHashObject(m), nil)
}

// parseLnkFields parses a shell link and reports which of the two ways it can
// fail happened: the bytes were never a link, or a link came apart under the
// parser.
//
// The difference matters to a jump list. An automatic one declares each numbered
// stream to be a shell link, so any failure there is a destination lost. A
// custom one is a run of links found by scanning for their signature, so a
// failure there is usually a byte sequence that was never a link -- a path
// string that happens to contain the signature will do it -- and counting those
// would report losses that did not happen.
//
// It also takes the recover, which belongs here rather than in a builtin: this
// is the only place that knows a panic is one link's and not the file's.
// jumplist_parse used to lose every entry to one damaged stream because the
// nearest recover was the one wrapping the whole parse. What reaches the caller
// is a sentence about the link, not the runtime's description of a slice.
//
// The capacity is cut to the length first. A slice expression may reach past the
// length as far as the capacity, so a field declaring more bytes than the link
// holds read whatever was in the allocator's slack -- and reported it, in the
// case of local_base_path, as a file path. Cutting the capacity makes every such
// read fail instead, and makes it fail the same way whether the bytes came from
// os.ReadFile, which leaves slack, or from make([]byte, size), which does not
// (M26-ART-011).
func parseLnkFields(data []byte) (fields map[string]object.Object, damaged bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			fields, damaged, err = nil, true, fmt.Errorf(
				"the shell link is damaged: a field it declares reaches past the end of the link (%v)", r)
		}
	}()
	fields, err = parseLnkBody(data[:len(data):len(data)])
	return fields, false, err
}

// parseLnkBody is the link-structure parser, behind a variable so that the
// recover above, and the counts that depend on it, have something that can fail.
//
// No crafted link makes this panic any more: a field reaching past the end of
// the link was M26-ART-011 and it is guarded, and the capacity cut closes the
// rest. Without a seam the recover would be untested, and jumplist_parse's
// unreadable_entries could never be anything but zero on a custom list -- a
// count that can only ever say nothing was lost, with an authority it has not
// got. The missing recover was in exactly that state until a damaged stream
// proved it.
var parseLnkBody = parseLnkBytes

// parseLnkBytes parses a shell-link (MS-SHLLINK) structure from a byte slice and
// returns its fields. Tolerates trailing bytes after the link.
//
// Callers go through parseLnkFields, which supplies the capacity cut and the
// recover. This function assumes both.
func parseLnkBytes(data []byte) (map[string]object.Object, error) {
	if len(data) < 76 || binary.LittleEndian.Uint32(data[0:4]) != 0x0000004C {
		return nil, fmt.Errorf("not a shell link (bad header)")
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

	decoded := decodeLnkFlags(flags)

	return map[string]object.Object{
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
	}, nil
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
	// The guard above established start+16 bytes; the offset at +16 needs four
	// more. A LinkInfo that sets the flag and then ends is a link with no local
	// base path in it, which is what an empty one says -- not a reason to
	// abandon the header fields that were read before it.
	if linkInfoFlags&0x01 != 0 && start+20 <= len(data) { // VolumeIDAndLocalBasePath
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
