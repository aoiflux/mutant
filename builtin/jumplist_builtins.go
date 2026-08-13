package builtin

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/richardlehane/mscfb"

	"mutant/object"
)

// cfbMagic is the OLE Compound File Binary signature (automaticDestinations).
var cfbMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// lnkHeaderSig is the start of every shell link: HeaderSize 0x4C followed by the
// LinkCLSID {00021401-0000-0000-C000-000000000046}.
var lnkHeaderSig = []byte{
	0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x46,
}

// JumplistParse decodes a Windows Jump List (recent/pinned destinations). It
// auto-detects the two on-disk formats: an *.automaticDestinations-ms (an OLE
// compound file whose numbered streams are shell links, plus a DestList stream
// holding MRU/access metadata) and a *.customDestinations-ms (a sequence of
// concatenated shell links). Each entry merges the DestList metadata with the
// embedded shell-link target. Returns {type, format_version, entry_count,
// pinned_count, entries} paired with an error.
func JumplistParse(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("jumplist_parse: panic during parse: %v", r))
		}
	}()

	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg("jumplist_parse", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return resultAndError(nil, newError("jumplist_parse: %s", err.Error()))
	}

	if len(data) >= 8 && bytes.Equal(data[0:8], cfbMagic) {
		return parseAutomaticJumplist(data)
	}
	return parseCustomJumplist(data)
}

// destEntry is the per-destination metadata from the DestList stream.
type destEntry struct {
	streamID   uint32
	hostname   string
	lastAccess int64
	pinned     bool
	path       string
}

func parseAutomaticJumplist(data []byte) object.Object {
	r, err := mscfb.New(bytes.NewReader(data))
	if err != nil {
		return resultAndError(nil, newError("jumplist_parse: %s", err.Error()))
	}

	destByID := map[uint32]destEntry{}
	lnkByID := map[uint32]map[string]object.Object{}
	var version, total, pinned uint32
	var order []uint32

	for {
		f, err := r.Next()
		if err == io.EOF || err != nil {
			break
		}
		if f.Size <= 0 || f.Size > 64<<20 {
			continue
		}
		buf := make([]byte, f.Size)
		if _, err := io.ReadFull(f, buf); err != nil {
			continue
		}

		if strings.EqualFold(f.Name, "DestList") {
			version, total, pinned = destListHeader(buf)
			for _, de := range parseDestList(buf) {
				if _, seen := destByID[de.streamID]; !seen {
					order = append(order, de.streamID)
				}
				destByID[de.streamID] = de
			}
			continue
		}
		// Numbered stream (hex) → a shell link.
		id, perr := strconv.ParseUint(strings.TrimSpace(f.Name), 16, 32)
		if perr != nil {
			continue
		}
		if m, lerr := parseLnkBytes(buf); lerr == nil {
			lnkByID[uint32(id)] = m
		}
	}

	// Include any LNK streams the DestList didn't reference (order after DestList).
	seen := map[uint32]bool{}
	for _, id := range order {
		seen[id] = true
	}
	extra := make([]uint32, 0)
	for id := range lnkByID {
		if !seen[id] {
			extra = append(extra, id)
		}
	}
	sort.Slice(extra, func(i, j int) bool { return extra[i] < extra[j] })
	order = append(order, extra...)

	entries := make([]object.Object, 0, len(order))
	for _, id := range order {
		m := map[string]object.Object{"stream_id": intObj(int64(id))}
		if de, ok := destByID[id]; ok {
			m["hostname"] = stringObj(de.hostname)
			m["last_access"] = intObj(de.lastAccess)
			m["last_access_iso"] = stringObj(unixToISO(de.lastAccess))
			m["pinned"] = boolObj(de.pinned)
			m["dest_path"] = stringObj(de.path)
		}
		if lnk, ok := lnkByID[id]; ok {
			m["target"] = lnk["local_base_path"]
			m["arguments"] = lnk["arguments"]
			m["working_dir"] = lnk["working_dir"]
			m["relative_path"] = lnk["relative_path"]
			m["name"] = lnk["name"]
			m["creation_time"] = lnk["creation_time"]
			m["write_time"] = lnk["write_time"]
			m["write_iso"] = lnk["write_iso"]
		}
		entries = append(entries, makeHashObject(m))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"type":           stringObj("automatic"),
		"format_version": intObj(int64(version)),
		"entry_count":    intObj(int64(total)),
		"pinned_count":   intObj(int64(pinned)),
		"entries":        &object.Array{Elements: entries},
	}), nil)
}

// destListHeader reads the 32-byte DestList header: version, entry count, pinned
// count.
func destListHeader(buf []byte) (version, total, pinned uint32) {
	if len(buf) < 32 {
		return 0, 0, 0
	}
	return binary.LittleEndian.Uint32(buf[0:4]),
		binary.LittleEndian.Uint32(buf[4:8]),
		binary.LittleEndian.Uint32(buf[8:12])
}

// parseDestList walks the variable-length DestList entries. Field offsets are
// stable up to the pin-status field (0x6C); the path-size field then sits at
// 0x70 for v1 (Win7) and 0x74 for v3/v4 (Win8+/Win10), with a 4-byte trailer on
// v3/v4. Every access is bounds-checked; a malformed entry ends iteration.
func parseDestList(buf []byte) []destEntry {
	version, total, _ := destListHeader(buf)
	entries := make([]destEntry, 0, total)

	pathSizeOff := 0x70
	trailer := 0
	if version >= 3 {
		pathSizeOff = 0x74
		trailer = 4
	}

	off := 32
	for len(entries) < int(total) {
		if off+pathSizeOff+2 > len(buf) {
			break
		}
		de := destEntry{
			streamID:   binary.LittleEndian.Uint32(buf[off+0x58 : off+0x5C]),
			hostname:   trimZeros(buf[off+0x48 : off+0x58]),
			lastAccess: filetimeToUnix(binary.LittleEndian.Uint64(buf[off+0x64 : off+0x6C])),
			pinned:     binary.LittleEndian.Uint32(buf[off+0x6C:off+0x70]) != 0xFFFFFFFF,
		}
		pathChars := int(binary.LittleEndian.Uint16(buf[off+pathSizeOff : off+pathSizeOff+2]))
		pathStart := off + pathSizeOff + 2
		pathEnd := pathStart + pathChars*2
		if pathChars < 0 || pathChars > 2048 || pathEnd > len(buf) {
			break
		}
		de.path = decodeUTF16LE(buf[pathStart:pathEnd])
		entries = append(entries, de)
		off = pathEnd + trailer
	}
	return entries
}

// parseCustomJumplist handles *.customDestinations-ms — a header followed by
// concatenated shell links. Locates each shell link by its signature and parses
// it (parseLnkBytes tolerates the trailing bytes of the next link).
func parseCustomJumplist(data []byte) object.Object {
	entries := make([]object.Object, 0)
	for i := 0; i+len(lnkHeaderSig) <= len(data); {
		idx := bytes.Index(data[i:], lnkHeaderSig)
		if idx < 0 {
			break
		}
		start := i + idx
		if m, err := parseLnkBytes(data[start:]); err == nil {
			m["stream_id"] = intObj(int64(len(entries)))
			m["target"] = m["local_base_path"]
			entries = append(entries, makeHashObject(m))
		}
		i = start + len(lnkHeaderSig)
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"type":           stringObj("custom"),
		"format_version": intObj(0),
		"entry_count":    intObj(int64(len(entries))),
		"pinned_count":   intObj(0),
		"entries":        &object.Array{Elements: entries},
	}), nil)
}

func trimZeros(b []byte) string {
	end := len(b)
	for end > 0 && b[end-1] == 0 {
		end--
	}
	// Hostnames are ASCII; keep only printable bytes.
	out := make([]byte, 0, end)
	for _, c := range b[:end] {
		if c >= 0x20 && c < 0x7F {
			out = append(out, c)
		}
	}
	return string(out)
}
