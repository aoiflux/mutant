package builtin

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"

	"mutant/object"
)

// A pure-Go parser for Windows registry hives (regf binary format) — real hive
// reads, distinct from the JSON-fixture reg_* family. Handle-based, like the other
// parser families. Cells offsets in the format are relative to the first hbin at
// file offset 0x1000.

const hiveBinBase = 0x1000

type regfHive struct {
	data       []byte
	rootOffset uint32 // relative to hiveBinBase
}

type nkKey struct {
	name           string
	lastWrite      int64
	subkeyCount    uint32
	subkeyListRel  uint32
	valueCount     uint32
	valueListRel   uint32
	subkeyListNone bool
}

type vkValue struct {
	name      string
	dataSize  uint32
	dataOff   uint32
	dataType  uint32
	inlineRaw []byte // the raw 4 bytes of the data-offset field (for inline values)
}

var hiveStore = struct {
	sync.Mutex
	next  int64
	hives map[string]*regfHive
}{hives: map[string]*regfHive{}}

func openRegfHive(path string) (*regfHive, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < hiveBinBase || string(data[0:4]) != "regf" {
		return nil, fmt.Errorf("not a registry hive (bad regf header)")
	}
	rootOffset := binary.LittleEndian.Uint32(data[0x24:0x28])
	return &regfHive{data: data, rootOffset: rootOffset}, nil
}

// cell returns the data bytes of the cell at rel (relative to hiveBinBase), i.e.
// the bytes after the 4-byte cell size.
func (h *regfHive) cell(rel uint32) ([]byte, error) {
	abs := hiveBinBase + int(rel)
	if rel == 0xFFFFFFFF || abs < 0 || abs+4 > len(h.data) {
		return nil, fmt.Errorf("cell offset out of bounds")
	}
	size := int32(binary.LittleEndian.Uint32(h.data[abs : abs+4]))
	length := int(size)
	if length < 0 {
		length = -length // negative size => allocated cell
	}
	if length < 8 || abs+length > len(h.data) {
		return nil, fmt.Errorf("invalid cell length")
	}
	return h.data[abs+4 : abs+length], nil
}

func (h *regfHive) parseNK(rel uint32) (*nkKey, error) {
	c, err := h.cell(rel)
	if err != nil {
		return nil, err
	}
	if len(c) < 0x50 || string(c[0:2]) != "nk" {
		return nil, fmt.Errorf("not an nk record")
	}
	flags := binary.LittleEndian.Uint16(c[0x02:0x04])
	nameLen := int(binary.LittleEndian.Uint16(c[0x48:0x4A]))
	if 0x4C+nameLen > len(c) {
		return nil, fmt.Errorf("nk name out of bounds")
	}
	nameBytes := c[0x4C : 0x4C+nameLen]
	name := ""
	if flags&0x20 != 0 { // KEY_COMP_NAME: ASCII/Latin-1 name
		name = string(nameBytes)
	} else {
		name = decodeUTF16LE(nameBytes)
	}
	subkeyListRel := binary.LittleEndian.Uint32(c[0x1C:0x20])
	valueListRel := binary.LittleEndian.Uint32(c[0x28:0x2C])
	return &nkKey{
		name:           name,
		lastWrite:      filetimeToUnix(binary.LittleEndian.Uint64(c[0x04:0x0C])),
		subkeyCount:    binary.LittleEndian.Uint32(c[0x14:0x18]),
		subkeyListRel:  subkeyListRel,
		valueCount:     binary.LittleEndian.Uint32(c[0x24:0x28]),
		valueListRel:   valueListRel,
		subkeyListNone: subkeyListRel == 0xFFFFFFFF || binary.LittleEndian.Uint32(c[0x14:0x18]) == 0,
	}, nil
}

// subkeyOffsets returns the rel offsets of all subkey nk records, resolving the
// lf/lh/li/ri subkey-list structures.
func (h *regfHive) subkeyOffsets(nk *nkKey) []uint32 {
	if nk.subkeyListNone {
		return nil
	}
	return h.collectSubkeyList(nk.subkeyListRel, 0)
}

func (h *regfHive) collectSubkeyList(rel uint32, depth int) []uint32 {
	if depth > 32 {
		return nil
	}
	c, err := h.cell(rel)
	if err != nil || len(c) < 4 {
		return nil
	}
	sig := string(c[0:2])
	count := int(binary.LittleEndian.Uint16(c[2:4]))
	out := make([]uint32, 0, count)
	switch sig {
	case "lf", "lh": // {offset(4), hash(4)} entries
		for i := 0; i < count; i++ {
			base := 4 + i*8
			if base+4 > len(c) {
				break
			}
			out = append(out, binary.LittleEndian.Uint32(c[base:base+4]))
		}
	case "li": // {offset(4)} entries
		for i := 0; i < count; i++ {
			base := 4 + i*4
			if base+4 > len(c) {
				break
			}
			out = append(out, binary.LittleEndian.Uint32(c[base:base+4]))
		}
	case "ri": // list of subkey-list offsets -> recurse
		for i := 0; i < count; i++ {
			base := 4 + i*4
			if base+4 > len(c) {
				break
			}
			out = append(out, h.collectSubkeyList(binary.LittleEndian.Uint32(c[base:base+4]), depth+1)...)
		}
	}
	return out
}

func (h *regfHive) values(nk *nkKey) []*vkValue {
	if nk.valueCount == 0 || nk.valueListRel == 0xFFFFFFFF {
		return nil
	}
	c, err := h.cell(nk.valueListRel)
	if err != nil {
		return nil
	}
	out := make([]*vkValue, 0, nk.valueCount)
	for i := 0; i < int(nk.valueCount); i++ {
		base := i * 4
		if base+4 > len(c) {
			break
		}
		vk, err := h.parseVK(binary.LittleEndian.Uint32(c[base : base+4]))
		if err == nil {
			out = append(out, vk)
		}
	}
	return out
}

func (h *regfHive) parseVK(rel uint32) (*vkValue, error) {
	c, err := h.cell(rel)
	if err != nil {
		return nil, err
	}
	if len(c) < 0x14 || string(c[0:2]) != "vk" {
		return nil, fmt.Errorf("not a vk record")
	}
	nameLen := int(binary.LittleEndian.Uint16(c[0x02:0x04]))
	flags := binary.LittleEndian.Uint16(c[0x10:0x12])
	name := ""
	if nameLen > 0 && 0x14+nameLen <= len(c) {
		nameBytes := c[0x14 : 0x14+nameLen]
		if flags&0x01 != 0 { // VALUE_COMP_NAME: ASCII
			name = string(nameBytes)
		} else {
			name = decodeUTF16LE(nameBytes)
		}
	}
	return &vkValue{
		name:      name,
		dataSize:  binary.LittleEndian.Uint32(c[0x04:0x08]),
		dataOff:   binary.LittleEndian.Uint32(c[0x08:0x0C]),
		dataType:  binary.LittleEndian.Uint32(c[0x0C:0x10]),
		inlineRaw: append([]byte(nil), c[0x08:0x0C]...),
	}, nil
}

var regValueTypeNames = map[uint32]string{
	0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD",
	5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST",
	11: "REG_QWORD",
}

func (h *regfHive) valueData(vk *vkValue) (string, object.Object) {
	size := vk.dataSize & 0x7FFFFFFF
	inline := vk.dataSize&0x80000000 != 0

	var raw []byte
	if inline {
		n := int(size)
		if n > 4 {
			n = 4
		}
		raw = vk.inlineRaw[:n]
	} else {
		c, err := h.cell(vk.dataOff)
		if err != nil {
			return typeName(vk.dataType), stringObj("")
		}
		if int(size) <= len(c) {
			raw = c[:size]
		} else {
			raw = c
		}
	}

	switch vk.dataType {
	case 1, 2, 6: // REG_SZ / EXPAND_SZ / LINK
		return typeName(vk.dataType), stringObj(utf16leToString(raw))
	case 4: // REG_DWORD (LE)
		if len(raw) >= 4 {
			return typeName(vk.dataType), intObj(int64(binary.LittleEndian.Uint32(raw)))
		}
	case 5: // REG_DWORD_BIG_ENDIAN
		if len(raw) >= 4 {
			return typeName(vk.dataType), intObj(int64(binary.BigEndian.Uint32(raw)))
		}
	case 11: // REG_QWORD (LE)
		if len(raw) >= 8 {
			return typeName(vk.dataType), intObj(int64(binary.LittleEndian.Uint64(raw)))
		}
	case 7: // REG_MULTI_SZ
		parts := splitUTF16MultiSZ(raw)
		elems := make([]object.Object, len(parts))
		for i, p := range parts {
			elems[i] = stringObj(p)
		}
		return typeName(vk.dataType), &object.Array{Elements: elems}
	}
	// REG_BINARY and everything else -> hex
	return typeName(vk.dataType), stringObj(hex.EncodeToString(raw))
}

func typeName(t uint32) string {
	if n, ok := regValueTypeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("REG_UNKNOWN(%d)", t)
}

func (h *regfHive) findKey(path string) (*nkKey, error) {
	nk, err := h.parseNK(h.rootOffset)
	if err != nil {
		return nil, err
	}
	path = strings.Trim(strings.ReplaceAll(path, "/", "\\"), "\\")
	if path == "" {
		return nk, nil
	}
	for _, part := range strings.Split(path, "\\") {
		if part == "" {
			continue
		}
		var next *nkKey
		for _, so := range h.subkeyOffsets(nk) {
			sk, err := h.parseNK(so)
			if err == nil && strings.EqualFold(sk.name, part) {
				next = sk
				break
			}
		}
		if next == nil {
			return nil, fmt.Errorf("key not found: %s", part)
		}
		nk = next
	}
	return nk, nil
}

func utf16leToString(b []byte) string {
	s := decodeUTF16LE(b)
	return strings.TrimRight(s, "\x00")
}

func splitUTF16MultiSZ(b []byte) []string {
	full := decodeUTF16LE(b)
	parts := strings.Split(full, "\x00")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// --- builtins ---

func resolveHive(arg object.Object, op string) (*regfHive, *object.Error) {
	handle, ok := arg.(*object.String)
	if !ok {
		return nil, newError("argument 1 to `%s` must be STRING handle, got %s", op, arg.Type())
	}
	hiveStore.Lock()
	hive, found := hiveStore.hives[handle.Value]
	hiveStore.Unlock()
	if !found {
		return nil, newError("%s: invalid hive handle %q (call hive_open first)", op, handle.Value)
	}
	return hive, nil
}

func HiveOpen(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("hive_open: panic during parse: %v", r))
		}
	}()
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg("hive_open", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	hive, err := openRegfHive(path)
	if err != nil {
		return resultAndError(nil, newError("hive_open: %s", err.Error()))
	}
	hiveStore.Lock()
	hiveStore.next++
	handle := fmt.Sprintf("hive-%d", hiveStore.next)
	hiveStore.hives[handle] = hive
	hiveStore.Unlock()
	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handle),
		"path":   stringObj(path),
	}), nil)
}

func HiveClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	handle, errObj := requireStringArg("hive_close", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	hiveStore.Lock()
	_, ok := hiveStore.hives[handle]
	delete(hiveStore.hives, handle)
	hiveStore.Unlock()
	if !ok {
		return resultAndError(nil, newError("hive_close: invalid handle %q", handle))
	}
	return resultAndError(boolObj(true), nil)
}

func HiveKeyInfo(args ...object.Object) (result object.Object) {
	defer hiveRecover("hive_key_info", &result)
	hive, path, errObj := hiveHandleAndPath("hive_key_info", args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	nk, err := hive.findKey(path)
	if err != nil {
		return resultAndError(nil, newError("hive_key_info: %s", err.Error()))
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"name":           stringObj(nk.name),
		"last_write":     intObj(nk.lastWrite),
		"last_write_iso": stringObj(unixToISO(nk.lastWrite)),
		"subkey_count":   intObj(int64(nk.subkeyCount)),
		"value_count":    intObj(int64(nk.valueCount)),
	}), nil)
}

func HiveListKeys(args ...object.Object) (result object.Object) {
	defer hiveRecover("hive_list_keys", &result)
	hive, path, errObj := hiveHandleAndPath("hive_list_keys", args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	nk, err := hive.findKey(path)
	if err != nil {
		return resultAndError(nil, newError("hive_list_keys: %s", err.Error()))
	}
	names := make([]object.Object, 0)
	for _, so := range hive.subkeyOffsets(nk) {
		if sk, err := hive.parseNK(so); err == nil {
			names = append(names, stringObj(sk.name))
		}
	}
	return resultAndError(&object.Array{Elements: names}, nil)
}

func HiveListValues(args ...object.Object) (result object.Object) {
	defer hiveRecover("hive_list_values", &result)
	hive, path, errObj := hiveHandleAndPath("hive_list_values", args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	nk, err := hive.findKey(path)
	if err != nil {
		return resultAndError(nil, newError("hive_list_values: %s", err.Error()))
	}
	out := make([]object.Object, 0)
	for _, vk := range hive.values(nk) {
		tname, data := hive.valueData(vk)
		name := vk.name
		if name == "" {
			name = "(default)"
		}
		out = append(out, makeHashObject(map[string]object.Object{
			"name": stringObj(name),
			"type": stringObj(tname),
			"data": data,
		}))
	}
	return resultAndError(&object.Array{Elements: out}, nil)
}

func HiveGetValue(args ...object.Object) (result object.Object) {
	defer hiveRecover("hive_get_value", &result)
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3 (handle, keypath, valuename)", len(args)))
	}
	hive, errObj := resolveHive(args[0], "hive_get_value")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	path, errObj := requireStringArg("hive_get_value", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	valueName, errObj := requireStringArg("hive_get_value", args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	nk, err := hive.findKey(path)
	if err != nil {
		return resultAndError(nil, newError("hive_get_value: %s", err.Error()))
	}
	for _, vk := range hive.values(nk) {
		if strings.EqualFold(vk.name, valueName) {
			tname, data := hive.valueData(vk)
			return resultAndError(makeHashObject(map[string]object.Object{
				"name": stringObj(vk.name),
				"type": stringObj(tname),
				"data": data,
			}), nil)
		}
	}
	return resultAndError(nil, newError("hive_get_value: value %q not found under %q", valueName, path))
}

func hiveHandleAndPath(op string, args []object.Object) (*regfHive, string, *object.Error) {
	if len(args) != 1 && len(args) != 2 {
		return nil, "", newError("wrong number of arguments to `%s`. got=%d, want=1 or 2", op, len(args))
	}
	hive, errObj := resolveHive(args[0], op)
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
	return hive, path, nil
}

func hiveRecover(op string, result *object.Object) {
	if r := recover(); r != nil {
		*result = resultAndError(nil, newError("%s: panic during parse: %v", op, r))
	}
}
