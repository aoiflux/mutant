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
// extracted blob file. Supports the Win8/Win8.1/Win10 entry format ("10ts"/"00ts").
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
	path, errObj := requireStringArg("shimcache_parse", args[0], 1)
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

// decodeShimcache parses the Win8/Win8.1/Win10 AppCompatCache entry format.
func decodeShimcache(blob []byte) ([]shimEntry, string, error) {
	if len(blob) < 4 {
		return nil, "", fmt.Errorf("blob too short")
	}
	headerSize := int(binary.LittleEndian.Uint32(blob[0:4]))
	if headerSize != 0x30 && headerSize != 0x34 {
		return nil, "", fmt.Errorf("unsupported AppCompatCache header 0x%x (only Win8/Win8.1/Win10 are supported)", headerSize)
	}

	entries := make([]shimEntry, 0)
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

		lastModified := int64(0)
		if p+8 <= entryEnd {
			lastModified = filetimeToUnix(binary.LittleEndian.Uint64(blob[p : p+8]))
		}

		entries = append(entries, shimEntry{path: path, lastModified: lastModified})
		off = entryEnd
	}
	return entries, "win8_win10", nil
}
