package builtin

import (
	"encoding/binary"
	"fmt"
	"os"

	"mutant/object"
)

// ShimcacheParse decodes the Windows AppCompatCache (shimcache) — program
// execution/presence evidence stored as a REG_BINARY blob in the SYSTEM hive.
// Accepts a SYSTEM hive file (it locates the AppCompatCache value) or a raw
// extracted blob file. Reads the Win8 ("00ts"), Win8.1 ("10ts" at a 0x80 header)
// and Win10/11 ("10ts" at 0x30 or 0x34) entry layouts, and reports which one it
// read as "win8", "win81" or "win10".
// Returns {version, count, entries:[{position, path, last_modified, last_modified_iso}]}.
func ShimcacheParse(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("shimcache_parse: panic during parse: %v", r))
		}
	}()

	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg(BuiltinNameShimcacheParse, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return resultAndError(nil, newError("shimcache_parse: %s", err.Error()))
	}

	blob := data
	if len(data) >= 4 && string(data[0:4]) == "regf" {
		hive, herr := openRegfHive(path)
		if herr != nil {
			return resultAndError(nil, newError("shimcache_parse: %s", herr.Error()))
		}
		b, ferr := findAppCompatCacheBlob(hive)
		if ferr != nil {
			return resultAndError(nil, newError("shimcache_parse: %s", ferr.Error()))
		}
		blob = b
	}

	entries, version, err := decodeShimcache(blob)
	if err != nil {
		return resultAndError(nil, newError("shimcache_parse: %s", err.Error()))
	}

	out := make([]object.Object, len(entries))
	for i, e := range entries {
		out[i] = makeHashObject(map[string]object.Object{
			"position":          intObj(int64(i)),
			"path":              stringObj(e.path),
			"last_modified":     intObj(e.lastModified),
			"last_modified_iso": stringObj(unixToISO(e.lastModified)),
		})
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"version": stringObj(version),
		"count":   intObj(int64(len(entries))),
		"entries": &object.Array{Elements: out},
	}), nil)
}

type shimEntry struct {
	path         string
	lastModified int64
}

// findAppCompatCacheBlob locates the AppCompatCache REG_BINARY value in a SYSTEM
// hive, preferring the ControlSet named by Select\Current.
func findAppCompatCacheBlob(hive *regfHive) ([]byte, error) {
	controlSets := make([]string, 0, 3)
	if sel, err := hive.findKey("Select"); err == nil {
		if raw, ok := hive.findValueRaw(sel, "Current"); ok && len(raw) >= 4 {
			controlSets = append(controlSets, fmt.Sprintf("ControlSet%03d", binary.LittleEndian.Uint32(raw)))
		}
	}
	controlSets = append(controlSets, "ControlSet001", "ControlSet002")

	seen := map[string]bool{}
	for _, cs := range controlSets {
		if seen[cs] {
			continue
		}
		seen[cs] = true
		for _, sub := range []string{`\Control\Session Manager\AppCompatCache`, `\Control\Session Manager\AppCompatibility`} {
			if nk, err := hive.findKey(cs + sub); err == nil {
				if raw, ok := hive.findValueRaw(nk, "AppCompatCache"); ok {
					return raw, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("AppCompatCache value not found in SYSTEM hive")
}

// AppCompatCache header sizes, which select the entry layout as well as the
// length of the statistics block that precedes the entries. 0x80 is Mandiant
// ShimCacheParser's WIN8_STATS_SIZE, shared by Win8 and Win8.1; Win10 shortened
// it to 0x30, and some Win10 builds write 0x34.
const (
	shimHeaderWin8     = 0x80
	shimHeaderWin10    = 0x30
	shimHeaderWin10Alt = 0x34
)

// decodeShimcache parses the Win8, Win8.1 and Win10/11 AppCompatCache entry
// formats and names which one it read.
//
// The header size chooses the layout, and it is not only a length to skip. Both
// 0x80 formats put a flags word and an unknown word between the path and the
// FILETIME, which the Win10 format does not have, and Win8 ("00ts") puts a
// package-data length and its bytes before those. Reading a 0x80 entry at the
// Win10 layout takes the flags and the unknown word for the two halves of the
// timestamp, which yields a last_modified that is wrong rather than absent --
// so the header check that used to refuse these two versions is replaced by
// three layouts, not relaxed into one.
func decodeShimcache(blob []byte) ([]shimEntry, string, error) {
	if len(blob) < 4 {
		return nil, "", fmt.Errorf("blob too short")
	}
	headerSize := int(binary.LittleEndian.Uint32(blob[0:4]))
	win8Layout := false
	switch headerSize {
	case shimHeaderWin8:
		win8Layout = true
	case shimHeaderWin10, shimHeaderWin10Alt:
	default:
		return nil, "", fmt.Errorf("unsupported AppCompatCache header 0x%x (Win8 and Win8.1 are 0x%x, Win10/11 are 0x%x or 0x%x)",
			headerSize, shimHeaderWin8, shimHeaderWin10, shimHeaderWin10Alt)
	}

	entries := make([]shimEntry, 0)
	// The version is taken from the entries rather than from the header,
	// because the header the two Win8 releases share does not distinguish
	// them: "00ts" is Win8 and "10ts" at a 0x80 header is Win8.1.
	version := ""
	off := headerSize
	for off+12 <= len(blob) {
		sig := string(blob[off : off+4])
		if sig != "10ts" && sig != "00ts" {
			break
		}
		cacheEntrySize := int(binary.LittleEndian.Uint32(blob[off+8 : off+12]))
		entryStart := off + 12
		entryEnd := entryStart + cacheEntrySize
		if cacheEntrySize <= 0 || entryEnd > len(blob) {
			break
		}

		p := entryStart
		if p+2 > entryEnd {
			break
		}
		pathSize := int(binary.LittleEndian.Uint16(blob[p : p+2]))
		p += 2
		if p+pathSize > entryEnd {
			break
		}
		path := decodeUTF16LE(blob[p : p+pathSize])
		p += pathSize

		if version == "" {
			switch {
			case !win8Layout:
				version = "win10"
			case sig == "00ts":
				version = "win8"
			default:
				version = "win81"
			}
		}

		if win8Layout {
			// Win8 only: a package-data length and the bytes it counts.
			if sig == "00ts" {
				if p+2 > entryEnd {
					break
				}
				packageSize := int(binary.LittleEndian.Uint16(blob[p : p+2]))
				p += 2
				if p+packageSize > entryEnd {
					break
				}
				p += packageSize
			}
			// Both 0x80 layouts: flags and one unknown word.
			if p+8 > entryEnd {
				break
			}
			p += 8
		}

		lastModified := int64(0)
		if p+8 <= entryEnd {
			lastModified = filetimeToUnix(binary.LittleEndian.Uint64(blob[p : p+8]))
		}

		entries = append(entries, shimEntry{path: path, lastModified: lastModified})
		off = entryEnd
	}
	if version == "" {
		// No entry was read, so no entry named the version. The header is the
		// only thing left that is known, and for 0x80 it names two releases.
		if win8Layout {
			version = "win8_win81"
		} else {
			version = "win10"
		}
	}
	return entries, version, nil
}
