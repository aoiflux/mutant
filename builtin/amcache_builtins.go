package builtin

import (
	"strings"

	"mutant/object"
)

// AmcacheParse parses an Amcache.hve registry hive (program execution/presence
// evidence) into file entries. Supports the modern InventoryApplicationFile layout
// (Win8+) and the legacy Root\File\{volume}\{fileref} layout, built on the pure-Go
// regf hive parser. Returns {format, count, entries}. Returns (result, err).
func AmcacheParse(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("amcache_parse: panic during parse: %v", r))
		}
	}()

	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg("amcache_parse", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	hive, err := openRegfHive(path)
	if err != nil {
		return resultAndError(nil, newError("amcache_parse: %s", err.Error()))
	}

	// Modern layout: (Root\)InventoryApplicationFile
	for _, p := range []string{`Root\InventoryApplicationFile`, `InventoryApplicationFile`} {
		if nk, err := hive.findKey(p); err == nil {
			return amcacheInventory(hive, nk)
		}
	}
	// Legacy layout: (Root\)File\{volume}\{fileref}
	for _, p := range []string{`Root\File`, `File`} {
		if nk, err := hive.findKey(p); err == nil {
			return amcacheFileFormat(hive, nk)
		}
	}
	return resultAndError(nil, newError("amcache_parse: not an Amcache hive (no InventoryApplicationFile or File key)"))
}

func amcacheInventory(hive *regfHive, nk *nkKey) object.Object {
	entries := make([]object.Object, 0)
	for _, so := range hive.subkeyOffsets(nk) {
		sk, err := hive.parseNK(so)
		if err != nil {
			continue
		}
		m := hive.valueMap(sk)
		entries = append(entries, makeHashObject(map[string]object.Object{
			"key":        stringObj(sk.name),
			"path":       stringObj(amcacheStr(m, "lowercaselongpath")),
			"name":       stringObj(amcacheStr(m, "name")),
			"sha1":       stringObj(stripAmcacheFileID(amcacheStr(m, "fileid"))),
			"publisher":  stringObj(amcacheStr(m, "publisher")),
			"version":    stringObj(amcacheStr(m, "version")),
			"product":    stringObj(amcacheStr(m, "productname")),
			"size":       amcacheValue(m, "size"),
			"last_write": intObj(sk.lastWrite),
		}))
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"format":  stringObj("inventory_application_file"),
		"count":   intObj(int64(len(entries))),
		"entries": &object.Array{Elements: entries},
	}), nil)
}

func amcacheFileFormat(hive *regfHive, nk *nkKey) object.Object {
	entries := make([]object.Object, 0)
	for _, volSo := range hive.subkeyOffsets(nk) {
		volNk, err := hive.parseNK(volSo)
		if err != nil {
			continue
		}
		for _, fileSo := range hive.subkeyOffsets(volNk) {
			fileNk, err := hive.parseNK(fileSo)
			if err != nil {
				continue
			}
			m := hive.valueMap(fileNk)
			entries = append(entries, makeHashObject(map[string]object.Object{
				"key":        stringObj(fileNk.name),
				"volume":     stringObj(volNk.name),
				"path":       stringObj(amcacheStr(m, "15")),
				"sha1":       stringObj(stripAmcacheFileID(amcacheStr(m, "101"))),
				"company":    stringObj(amcacheStr(m, "1")),
				"product":    stringObj(amcacheStr(m, "0")),
				"size":       amcacheValue(m, "6"),
				"last_write": intObj(fileNk.lastWrite),
			}))
		}
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"format":  stringObj("file"),
		"count":   intObj(int64(len(entries))),
		"entries": &object.Array{Elements: entries},
	}), nil)
}

func amcacheStr(m map[string]object.Object, key string) string {
	if v, ok := m[key].(*object.String); ok {
		return v.Value
	}
	return ""
}

func amcacheValue(m map[string]object.Object, key string) object.Object {
	if v, ok := m[key]; ok {
		return v
	}
	return globalNullObject()
}

// stripAmcacheFileID normalizes a FileId/SHA-1 value: Amcache stores it as a
// zero-padded "0000" prefix followed by the 40-char SHA-1.
func stripAmcacheFileID(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	if len(id) >= 44 && strings.HasPrefix(id, "0000") {
		return id[4:]
	}
	return id
}
