package builtin

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"mutant/object"
)

type registryHive struct {
	SourcePath string
	Keys       map[string]registryKey
	Deleted    []string
	Timeline   []map[string]any
}

type registryKey struct {
	Path      string
	NormPath  string
	LastWrite string
	Values    map[string]any
}

var registryStore = struct {
	sync.RWMutex
	nextID int64
	hives  map[string]*registryHive
}{
	nextID: 0,
	hives:  map[string]*registryHive{},
}

func RegOpenHive(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `reg_open_hive` must be STRING, got %s", args[0].Type()))
	}

	hive, errObj := loadRegistryHiveFromJSON(pathObj.Value)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	registryStore.Lock()
	registryStore.nextID++
	handle := fmt.Sprintf("reg-hive-%d", registryStore.nextID)
	registryStore.hives[handle] = hive
	registryStore.Unlock()

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle":     stringObj(handle),
		"path":       stringObj(pathObj.Value),
		"keys_count": intObj(int64(len(hive.Keys))),
		"status":     stringObj("ok"),
	}), nil)
}

func RegEnumKeys(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	hive, errObj := resolveRegistryHive(args[0], "reg_enum_keys")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `reg_enum_keys` must be STRING, got %s", args[1].Type()))
	}

	parentPath := normalizeRegistryPath(pathObj.Value)
	children := make(map[string]registryKey)
	for _, key := range hive.Keys {
		if parentPath == "" {
			continue
		}
		if key.NormPath == parentPath {
			continue
		}
		prefix := parentPath + `\`
		if !strings.HasPrefix(key.NormPath, prefix) {
			continue
		}
		remainder := strings.TrimPrefix(key.NormPath, prefix)
		if strings.Contains(remainder, `\`) {
			continue
		}
		children[key.NormPath] = key
	}

	names := make([]string, 0, len(children))
	for _, key := range children {
		names = append(names, key.Path)
	}
	sort.Strings(names)

	out := make([]object.Object, len(names))
	for i, name := range names {
		out[i] = stringObj(name)
	}
	return resultAndError(&object.Array{Elements: out}, nil)
}

func RegEnumValues(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	hive, errObj := resolveRegistryHive(args[0], "reg_enum_values")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `reg_enum_values` must be STRING, got %s", args[1].Type()))
	}

	key, found := hive.Keys[normalizeRegistryPath(pathObj.Value)]
	if !found {
		return resultAndError(nil, newError("reg_enum_values: key not found: %s", pathObj.Value))
	}

	names := make([]string, 0, len(key.Values))
	for name := range key.Values {
		names = append(names, name)
	}
	sort.Strings(names)

	values := make([]object.Object, 0, len(names))
	for _, name := range names {
		valueObj, convErr := jsonValueToObject(key.Values[name])
		if convErr != nil {
			return resultAndError(nil, newError("reg_enum_values: conversion error for %s: %s", name, convErr.Error()))
		}
		values = append(values, makeHashObject(map[string]object.Object{
			"name": stringObj(name),
			"type": stringObj(registryTypeName(key.Values[name])),
			"data": valueObj,
		}))
	}
	return resultAndError(&object.Array{Elements: values}, nil)
}

func RegGetValue(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}

	hive, errObj := resolveRegistryHive(args[0], "reg_get_value")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `reg_get_value` must be STRING, got %s", args[1].Type()))
	}
	nameObj, ok := args[2].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `reg_get_value` must be STRING, got %s", args[2].Type()))
	}

	key, found := hive.Keys[normalizeRegistryPath(pathObj.Value)]
	if !found {
		return resultAndError(nil, newError("reg_get_value: key not found: %s", pathObj.Value))
	}
	value, found := key.Values[nameObj.Value]
	if !found {
		return resultAndError(nil, newError("reg_get_value: value not found: %s", nameObj.Value))
	}

	valueObj, convErr := jsonValueToObject(value)
	if convErr != nil {
		return resultAndError(nil, newError("reg_get_value: conversion error for %s: %s", nameObj.Value, convErr.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"name": stringObj(nameObj.Value),
		"type": stringObj(registryTypeName(value)),
		"data": valueObj,
	}), nil)
}

func RegDeletedKeys(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	hive, errObj := resolveRegistryHive(args[0], "reg_deleted_keys")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	out := make([]object.Object, len(hive.Deleted))
	for i, key := range hive.Deleted {
		out[i] = stringObj(key)
	}
	return resultAndError(&object.Array{Elements: out}, nil)
}

func RegTimeline(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	hive, errObj := resolveRegistryHive(args[0], "reg_timeline")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	events := make([]object.Object, 0, len(hive.Timeline))
	for _, event := range hive.Timeline {
		eventObj, convErr := jsonValueToObject(event)
		if convErr != nil {
			return resultAndError(nil, newError("reg_timeline: conversion error: %s", convErr.Error()))
		}
		hash, ok := eventObj.(*object.Hash)
		if !ok {
			continue
		}
		events = append(events, hash)
	}
	return resultAndError(&object.Array{Elements: events}, nil)
}

func resolveRegistryHive(obj object.Object, opName string) (*registryHive, *object.Error) {
	handleObj, ok := obj.(*object.String)
	if !ok {
		return nil, newError("argument 1 to `%s` must be STRING handle, got %s", opName, obj.Type())
	}

	registryStore.RLock()
	hive, found := registryStore.hives[handleObj.Value]
	registryStore.RUnlock()
	if !found {
		return nil, newError("%s: unknown hive handle: %s", opName, handleObj.Value)
	}
	return hive, nil
}

func loadRegistryHiveFromJSON(path string) (*registryHive, *object.Error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, newError("reg_open_hive: %s", err.Error())
	}

	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.UseNumber()
	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil {
		return nil, newError("reg_open_hive: invalid hive JSON: %s", err.Error())
	}

	keysRaw, ok := raw["keys"].([]any)
	if !ok {
		return nil, newError("reg_open_hive: hive JSON must contain array key `keys`")
	}

	hive := &registryHive{
		SourcePath: path,
		Keys:       map[string]registryKey{},
		Deleted:    []string{},
		Timeline:   []map[string]any{},
	}

	for i, item := range keysRaw {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, newError("reg_open_hive: key entry at index %d must be object", i)
		}
		pathRaw, ok := entry["path"].(string)
		if !ok || strings.TrimSpace(pathRaw) == "" {
			return nil, newError("reg_open_hive: key entry at index %d missing string `path`", i)
		}
		values := map[string]any{}
		if rawValues, ok := entry["values"].(map[string]any); ok {
			for name, value := range rawValues {
				values[name] = value
			}
		}
		lastWrite := ""
		if lw, ok := entry["last_write"].(string); ok {
			lastWrite = lw
		}

		norm := normalizeRegistryPath(pathRaw)
		hive.Keys[norm] = registryKey{
			Path:      pathRaw,
			NormPath:  norm,
			LastWrite: lastWrite,
			Values:    values,
		}
	}

	if deletedRaw, ok := raw["deleted_keys"].([]any); ok {
		for _, item := range deletedRaw {
			if s, ok := item.(string); ok {
				hive.Deleted = append(hive.Deleted, s)
			}
		}
		sort.Strings(hive.Deleted)
	}

	if timelineRaw, ok := raw["timeline"].([]any); ok {
		for _, item := range timelineRaw {
			entry, ok := item.(map[string]any)
			if ok {
				hive.Timeline = append(hive.Timeline, entry)
			}
		}
	}

	return hive, nil
}

func normalizeRegistryPath(path string) string {
	normalized := strings.ReplaceAll(path, "/", `\`)
	for strings.Contains(normalized, `\\`) {
		normalized = strings.ReplaceAll(normalized, `\\`, `\`)
	}
	normalized = strings.TrimSpace(normalized)
	normalized = strings.TrimRight(normalized, `\`)
	return strings.ToLower(normalized)
}

func registryTypeName(value any) string {
	switch value.(type) {
	case string:
		return "REG_SZ"
	case bool:
		return "REG_BOOL"
	case json.Number, float64, int, int64:
		return "REG_DWORD"
	case []any:
		return "REG_MULTI_SZ"
	case map[string]any:
		return "REG_BINARY"
	default:
		return "REG_UNKNOWN"
	}
}
