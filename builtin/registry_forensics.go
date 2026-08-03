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

// The reg_* family is a polymorphic registry front-end. reg_open dispatches on its
// input: a hive-JSON file, a real regf hive file (SOFTWARE/SYSTEM/NTUSER.DAT, …),
// or — when the input is not a file — a live Windows registry key path (HKLM\…).
// All three are exposed through the registryBackend interface below.

type regEntry struct {
	name string
	typ  string
	data object.Object
}

type registryBackend interface {
	sourceType() string
	enumKeys(path string) ([]string, error)
	enumValues(path string) ([]regEntry, error)
	getValue(path, name string) (regEntry, error)
	deletedKeys() []string
	timeline() []object.Object
	close()
}

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
	nextID   int64
	backends map[string]registryBackend
}{backends: map[string]registryBackend{}}

func RegOpen(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `reg_open` must be STRING, got %s", args[0].Type()))
	}

	backend, errObj := openRegistrySource(pathObj.Value)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	registryStore.Lock()
	registryStore.nextID++
	handle := fmt.Sprintf("reg-hive-%d", registryStore.nextID)
	registryStore.backends[handle] = backend
	registryStore.Unlock()

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle":      stringObj(handle),
		"path":        stringObj(pathObj.Value),
		"source_type": stringObj(backend.sourceType()),
		"status":      stringObj("ok"),
	}), nil)
}

// openRegistrySource dispatches: an existing file is a regf hive or hive-JSON;
// anything else is treated as a live registry path.
func openRegistrySource(path string) (registryBackend, *object.Error) {
	if info, statErr := os.Stat(path); statErr == nil && !info.IsDir() {
		header, _ := readFileHeader(path, 8)
		if len(header) >= 4 && string(header[:4]) == "regf" {
			hive, err := openRegfHive(path)
			if err != nil {
				return nil, newError("reg_open: %s", err.Error())
			}
			return &hiveRegistryBackend{hive: hive}, nil
		}
		jsonHive, errObj := loadRegistryHiveFromJSON(path)
		if errObj != nil {
			return nil, newError("reg_open: %q is not a regf hive and not valid hive JSON: %s", path, errObj.Message)
		}
		return &jsonRegistryBackend{hive: jsonHive}, nil
	}

	backend, err := openLiveRegistry(path)
	if err != nil {
		return nil, newError("reg_open: %q is not a file, and live-registry open failed: %s", path, err.Error())
	}
	return backend, nil
}

func readFileHeader(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	read, _ := f.Read(buf)
	return buf[:read], nil
}

func RegEnumKeys(args ...object.Object) object.Object {
	backend, path, errObj := registryHandleAndPath("reg_enum_keys", args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	names, err := backend.enumKeys(path)
	if err != nil {
		return resultAndError(nil, newError("reg_enum_keys: %s", err.Error()))
	}
	out := make([]object.Object, len(names))
	for i, name := range names {
		out[i] = stringObj(name)
	}
	return resultAndError(&object.Array{Elements: out}, nil)
}

func RegEnumValues(args ...object.Object) object.Object {
	backend, path, errObj := registryHandleAndPath("reg_enum_values", args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	entries, err := backend.enumValues(path)
	if err != nil {
		return resultAndError(nil, newError("reg_enum_values: %s", err.Error()))
	}
	out := make([]object.Object, len(entries))
	for i, e := range entries {
		out[i] = regEntryHash(e)
	}
	return resultAndError(&object.Array{Elements: out}, nil)
}

func RegGetValue(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	backend, errObj := resolveRegistryBackend(args[0], "reg_get_value")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	path, errObj := requireStringArg("reg_get_value", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	name, errObj := requireStringArg("reg_get_value", args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	entry, err := backend.getValue(path, name)
	if err != nil {
		return resultAndError(nil, newError("reg_get_value: %s", err.Error()))
	}
	return resultAndError(regEntryHash(entry), nil)
}

func RegDeletedKeys(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	backend, errObj := resolveRegistryBackend(args[0], "reg_deleted_keys")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	deleted := backend.deletedKeys()
	out := make([]object.Object, len(deleted))
	for i, k := range deleted {
		out[i] = stringObj(k)
	}
	return resultAndError(&object.Array{Elements: out}, nil)
}

func RegTimeline(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	backend, errObj := resolveRegistryBackend(args[0], "reg_timeline")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	return resultAndError(&object.Array{Elements: backend.timeline()}, nil)
}

func RegClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	handleObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `reg_close` must be STRING handle, got %s", args[0].Type()))
	}
	registryStore.Lock()
	backend, found := registryStore.backends[handleObj.Value]
	if found {
		delete(registryStore.backends, handleObj.Value)
	}
	registryStore.Unlock()
	if !found {
		return resultAndError(nil, newError("reg_close: unknown hive handle: %s", handleObj.Value))
	}
	backend.close()
	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handleObj.Value),
		"closed": boolObj(true),
		"status": stringObj("ok"),
	}), nil)
}

func regEntryHash(e regEntry) object.Object {
	return makeHashObject(map[string]object.Object{
		"name": stringObj(e.name),
		"type": stringObj(e.typ),
		"data": e.data,
	})
}

func registryHandleAndPath(op string, args []object.Object) (registryBackend, string, *object.Error) {
	if len(args) != 1 && len(args) != 2 {
		return nil, "", newError("wrong number of arguments to `%s`. got=%d, want=1 or 2", op, len(args))
	}
	backend, errObj := resolveRegistryBackend(args[0], op)
	if errObj != nil {
		return nil, "", errObj
	}
	path := ""
	if len(args) == 2 {
		p, errObj := requireStringArg(op, args[1], 2)
		if errObj != nil {
			return nil, "", errObj
		}
		path = p
	}
	return backend, path, nil
}

func resolveRegistryBackend(obj object.Object, opName string) (registryBackend, *object.Error) {
	handleObj, ok := obj.(*object.String)
	if !ok {
		return nil, newError("argument 1 to `%s` must be STRING handle, got %s", opName, obj.Type())
	}
	registryStore.RLock()
	backend, found := registryStore.backends[handleObj.Value]
	registryStore.RUnlock()
	if !found {
		return nil, newError("%s: unknown hive handle: %s", opName, handleObj.Value)
	}
	return backend, nil
}

// --- JSON backend (hive-JSON fixtures) ---

type jsonRegistryBackend struct{ hive *registryHive }

func (b *jsonRegistryBackend) sourceType() string { return "json" }

func (b *jsonRegistryBackend) enumKeys(path string) ([]string, error) {
	parentPath := normalizeRegistryPath(path)
	names := make([]string, 0)
	for _, key := range b.hive.Keys {
		if parentPath == "" || key.NormPath == parentPath {
			continue
		}
		prefix := parentPath + `\`
		if !strings.HasPrefix(key.NormPath, prefix) {
			continue
		}
		if strings.Contains(strings.TrimPrefix(key.NormPath, prefix), `\`) {
			continue
		}
		names = append(names, key.Path)
	}
	sort.Strings(names)
	return names, nil
}

func (b *jsonRegistryBackend) enumValues(path string) ([]regEntry, error) {
	key, found := b.hive.Keys[normalizeRegistryPath(path)]
	if !found {
		return nil, fmt.Errorf("key not found: %s", path)
	}
	names := make([]string, 0, len(key.Values))
	for name := range key.Values {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := make([]regEntry, 0, len(names))
	for _, name := range names {
		valueObj, convErr := jsonValueToObject(key.Values[name])
		if convErr != nil {
			return nil, fmt.Errorf("conversion error for %s: %s", name, convErr.Error())
		}
		entries = append(entries, regEntry{name: name, typ: registryTypeName(key.Values[name]), data: valueObj})
	}
	return entries, nil
}

func (b *jsonRegistryBackend) getValue(path, name string) (regEntry, error) {
	key, found := b.hive.Keys[normalizeRegistryPath(path)]
	if !found {
		return regEntry{}, fmt.Errorf("key not found: %s", path)
	}
	value, found := key.Values[name]
	if !found {
		return regEntry{}, fmt.Errorf("value not found: %s", name)
	}
	valueObj, convErr := jsonValueToObject(value)
	if convErr != nil {
		return regEntry{}, fmt.Errorf("conversion error for %s: %s", name, convErr.Error())
	}
	return regEntry{name: name, typ: registryTypeName(value), data: valueObj}, nil
}

func (b *jsonRegistryBackend) deletedKeys() []string { return b.hive.Deleted }

func (b *jsonRegistryBackend) timeline() []object.Object {
	events := make([]object.Object, 0, len(b.hive.Timeline))
	for _, event := range b.hive.Timeline {
		if eventObj, err := jsonValueToObject(event); err == nil {
			if hash, ok := eventObj.(*object.Hash); ok {
				events = append(events, hash)
			}
		}
	}
	return events
}

func (b *jsonRegistryBackend) close() {
	b.hive.Keys = map[string]registryKey{}
	b.hive.Deleted = nil
	b.hive.Timeline = nil
}

// --- regf hive-file backend ---

type hiveRegistryBackend struct{ hive *regfHive }

func (b *hiveRegistryBackend) sourceType() string { return "hive" }

func (b *hiveRegistryBackend) enumKeys(path string) ([]string, error) {
	nk, err := b.hive.findKey(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0)
	for _, so := range b.hive.subkeyOffsets(nk) {
		if sk, err := b.hive.parseNK(so); err == nil {
			names = append(names, sk.name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func (b *hiveRegistryBackend) enumValues(path string) ([]regEntry, error) {
	nk, err := b.hive.findKey(path)
	if err != nil {
		return nil, err
	}
	entries := make([]regEntry, 0)
	for _, vk := range b.hive.values(nk) {
		tname, data := b.hive.valueData(vk)
		name := vk.name
		if name == "" {
			name = "(default)"
		}
		entries = append(entries, regEntry{name: name, typ: tname, data: data})
	}
	return entries, nil
}

func (b *hiveRegistryBackend) getValue(path, name string) (regEntry, error) {
	nk, err := b.hive.findKey(path)
	if err != nil {
		return regEntry{}, err
	}
	for _, vk := range b.hive.values(nk) {
		if strings.EqualFold(vk.name, name) {
			tname, data := b.hive.valueData(vk)
			return regEntry{name: vk.name, typ: tname, data: data}, nil
		}
	}
	return regEntry{}, fmt.Errorf("value not found: %s", name)
}

// deletedKeys/timeline aren't recovered from a raw hive (would need unallocated
// cell carving); return empty rather than fabricating.
func (b *hiveRegistryBackend) deletedKeys() []string     { return nil }
func (b *hiveRegistryBackend) timeline() []object.Object { return nil }
func (b *hiveRegistryBackend) close()                    {}

// --- shared JSON hive loading / helpers (unchanged) ---

func loadRegistryHiveFromJSON(path string) (*registryHive, *object.Error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, newError("reg_open: %s", err.Error())
	}

	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.UseNumber()
	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil {
		return nil, newError("reg_open: invalid hive JSON: %s", err.Error())
	}

	keysRaw, ok := raw["keys"].([]any)
	if !ok {
		return nil, newError("reg_open: hive JSON must contain array key `keys`")
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
			return nil, newError("reg_open: key entry at index %d must be object", i)
		}
		pathRaw, ok := entry["path"].(string)
		if !ok || strings.TrimSpace(pathRaw) == "" {
			return nil, newError("reg_open: key entry at index %d missing string `path`", i)
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
		hive.Keys[norm] = registryKey{Path: pathRaw, NormPath: norm, LastWrite: lastWrite, Values: values}
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
			if entry, ok := item.(map[string]any); ok {
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
	const maxDWORD = 4294967295 // 0xFFFFFFFF
	dwordOrQword := func(fitsDWORD bool) string {
		if fitsDWORD {
			return "REG_DWORD"
		}
		return "REG_QWORD"
	}
	switch v := value.(type) {
	case string:
		return "REG_SZ"
	case bool:
		return "REG_DWORD" // Windows has no boolean type; booleans are REG_DWORD 0/1
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return dwordOrQword(i >= 0 && i <= maxDWORD)
		}
		return "REG_QWORD"
	case float64:
		return dwordOrQword(v >= 0 && v <= maxDWORD && v == float64(int64(v)))
	case int:
		return dwordOrQword(v >= 0 && int64(v) <= maxDWORD)
	case int64:
		return dwordOrQword(v >= 0 && v <= maxDWORD)
	case []any:
		return "REG_MULTI_SZ"
	case map[string]any:
		return "REG_BINARY"
	default:
		return "REG_UNKNOWN"
	}
}
