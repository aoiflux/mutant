//go:build windows

package builtin

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"

	"mutant/object"
)

// liveRegistryBackend reads the live Windows registry via x/sys/windows/registry
// (pure-Go, no cgo). The backend is opened at a root+base key; enum/get paths are
// relative to that base.
type liveRegistryBackend struct {
	root registry.Key
	base string
}

func openLiveRegistry(spec string) (registryBackend, error) {
	root, base, err := parseLiveRegistrySpec(spec)
	if err != nil {
		return nil, err
	}
	// Validate the key opens now so reg_open fails fast on a bad path.
	k, err := registry.OpenKey(root, base, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, fmt.Errorf("cannot open registry key %q: %w", spec, err)
	}
	k.Close()
	return &liveRegistryBackend{root: root, base: base}, nil
}

var liveRegistryRoots = map[string]registry.Key{
	"HKLM": registry.LOCAL_MACHINE, "HKEY_LOCAL_MACHINE": registry.LOCAL_MACHINE,
	"HKCU": registry.CURRENT_USER, "HKEY_CURRENT_USER": registry.CURRENT_USER,
	"HKCR": registry.CLASSES_ROOT, "HKEY_CLASSES_ROOT": registry.CLASSES_ROOT,
	"HKU": registry.USERS, "HKEY_USERS": registry.USERS,
	"HKCC": registry.CURRENT_CONFIG, "HKEY_CURRENT_CONFIG": registry.CURRENT_CONFIG,
}

func parseLiveRegistrySpec(spec string) (registry.Key, string, error) {
	spec = strings.Trim(strings.ReplaceAll(spec, "/", `\`), `\`)
	parts := strings.SplitN(spec, `\`, 2)
	root, ok := liveRegistryRoots[strings.ToUpper(parts[0])]
	if !ok {
		return 0, "", fmt.Errorf("unknown registry root %q (use HKLM/HKCU/HKCR/HKU/HKCC)", parts[0])
	}
	base := ""
	if len(parts) == 2 {
		base = parts[1]
	}
	return root, base, nil
}

func (b *liveRegistryBackend) sourceType() string { return "live" }

func (b *liveRegistryBackend) subPath(path string) string {
	sub := strings.Trim(strings.ReplaceAll(path, "/", `\`), `\`)
	switch {
	case b.base == "":
		return sub
	case sub == "":
		return b.base
	default:
		return b.base + `\` + sub
	}
}

func (b *liveRegistryBackend) enumKeys(path string) ([]string, error) {
	k, err := registry.OpenKey(b.root, b.subPath(path), registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

func (b *liveRegistryBackend) enumValues(path string) ([]regEntry, error) {
	k, err := registry.OpenKey(b.root, b.subPath(path), registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	entries := make([]regEntry, 0, len(names))
	for _, name := range names {
		entries = append(entries, readLiveRegistryValue(k, name))
	}
	return entries, nil
}

func (b *liveRegistryBackend) getValue(path, name string) (regEntry, error) {
	k, err := registry.OpenKey(b.root, b.subPath(path), registry.QUERY_VALUE)
	if err != nil {
		return regEntry{}, err
	}
	defer k.Close()
	return readLiveRegistryValue(k, name), nil
}

func readLiveRegistryValue(k registry.Key, name string) regEntry {
	displayName := name
	if displayName == "" {
		displayName = "(default)"
	}
	_, valType, err := k.GetValue(name, nil)
	if err != nil && err != registry.ErrShortBuffer {
		return regEntry{name: displayName, typ: "REG_NONE", data: stringObj("")}
	}
	switch valType {
	case registry.SZ, registry.EXPAND_SZ:
		s, _, _ := k.GetStringValue(name)
		typ := "REG_SZ"
		if valType == registry.EXPAND_SZ {
			typ = "REG_EXPAND_SZ"
		}
		return regEntry{name: displayName, typ: typ, data: stringObj(s)}
	case registry.DWORD:
		n, _, _ := k.GetIntegerValue(name)
		return regEntry{name: displayName, typ: "REG_DWORD", data: intObj(int64(n))}
	case registry.QWORD:
		n, _, _ := k.GetIntegerValue(name)
		return regEntry{name: displayName, typ: "REG_QWORD", data: intObj(int64(n))}
	case registry.MULTI_SZ:
		ss, _, _ := k.GetStringsValue(name)
		elems := make([]object.Object, len(ss))
		for i, s := range ss {
			elems[i] = stringObj(s)
		}
		return regEntry{name: displayName, typ: "REG_MULTI_SZ", data: &object.Array{Elements: elems}}
	case registry.BINARY:
		buf, _, _ := k.GetBinaryValue(name)
		return regEntry{name: displayName, typ: "REG_BINARY", data: stringObj(hex.EncodeToString(buf))}
	default:
		return regEntry{name: displayName, typ: fmt.Sprintf("REG_TYPE(%d)", valType), data: stringObj("")}
	}
}

func (b *liveRegistryBackend) deletedKeys() []string     { return nil }
func (b *liveRegistryBackend) timeline() []object.Object { return nil }
func (b *liveRegistryBackend) close()                    {}
