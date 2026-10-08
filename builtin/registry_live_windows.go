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
		// A name the OS has just listed can still fail to read: on a live system
		// a value can be deleted or retyped between the enumeration and the
		// read. That fails the call rather than dropping the value, because a
		// list presented as complete while silently short is M26-NET-004 one
		// level up.
		entry, err := readLiveRegistryValue(k, name)
		if err != nil {
			return nil, fmt.Errorf("reading value %q: %w", name, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (b *liveRegistryBackend) getValue(path, name string) (regEntry, error) {
	k, err := registry.OpenKey(b.root, b.subPath(path), registry.QUERY_VALUE)
	if err != nil {
		return regEntry{}, err
	}
	defer k.Close()
	entry, err := readLiveRegistryValue(k, name)
	if err == registry.ErrNotExist {
		return regEntry{}, errRegValueNotFound(name)
	}
	if err != nil {
		return regEntry{}, err
	}
	return entry, nil
}

// readLiveRegistryValue reads one value, or says why it could not.
//
// It used to return a bare regEntry and map every GetValue error -- including
// ERROR_FILE_NOT_FOUND for a value that is simply not there -- to an entry of
// type REG_NONE with empty data. getValue then handed that back with a nil
// error, so the live backend never said "not found" while the JSON and hive
// backends did, and absence was indistinguishable from a real present REG_NONE
// value, which does exist (M26-NET-004).
//
// The typed getters' errors were dropped too, with `s, _, _ :=`. Each getter is
// called only for a type it accepts -- GetStringValue takes SZ and EXPAND_SZ,
// GetIntegerValue DWORD and QWORD -- so an error from one of them is not a type
// mistake: it is the value being deleted or retyped between the call that read
// its type and the call that reads its data. That is a real failure on a live
// system and it now travels.
//
// A nil buffer is what makes the first call cheap: RegQueryValueEx with no
// output buffer reports the type and the size it would need. ErrShortBuffer is
// still tolerated, as before, rather than relied on not to happen.
func readLiveRegistryValue(k registry.Key, name string) (regEntry, error) {
	displayName := name
	if displayName == "" {
		displayName = "(default)"
	}
	_, valType, err := k.GetValue(name, nil)
	if err != nil && err != registry.ErrShortBuffer {
		return regEntry{}, err
	}
	switch valType {
	case registry.SZ, registry.EXPAND_SZ:
		s, _, err := k.GetStringValue(name)
		if err != nil {
			return regEntry{}, err
		}
		typ := "REG_SZ"
		if valType == registry.EXPAND_SZ {
			typ = "REG_EXPAND_SZ"
		}
		return regEntry{name: displayName, typ: typ, data: stringObj(s)}, nil
	case registry.DWORD:
		n, _, err := k.GetIntegerValue(name)
		if err != nil {
			return regEntry{}, err
		}
		return regEntry{name: displayName, typ: "REG_DWORD", data: intObj(int64(n))}, nil
	case registry.QWORD:
		n, _, err := k.GetIntegerValue(name)
		if err != nil {
			return regEntry{}, err
		}
		return regEntry{name: displayName, typ: "REG_QWORD", data: intObj(int64(n))}, nil
	case registry.MULTI_SZ:
		ss, _, err := k.GetStringsValue(name)
		if err != nil {
			return regEntry{}, err
		}
		elems := make([]object.Object, len(ss))
		for i, s := range ss {
			elems[i] = stringObj(s)
		}
		return regEntry{name: displayName, typ: "REG_MULTI_SZ", data: &object.Array{Elements: elems}}, nil
	case registry.BINARY:
		// GetBinaryValue allocates a fresh buffer per call, so raw is owned already
		// and needs no clone the way the regf backend's window into the hive does.
		buf, _, err := k.GetBinaryValue(name)
		if err != nil {
			return regEntry{}, err
		}
		return regEntry{name: displayName, typ: "REG_BINARY", data: stringObj(hex.EncodeToString(buf)), raw: buf}, nil
	default:
		// An unrecognised type reports no data on a live key, so there are no bytes
		// to attach either. The regf backend hex-encodes the same types instead of
		// dropping them; that difference predates this and is left alone here.
		return regEntry{name: displayName, typ: fmt.Sprintf("REG_TYPE(%d)", valType), data: stringObj("")}, nil
	}
}

func (b *liveRegistryBackend) deletedKeys() []string     { return nil }
func (b *liveRegistryBackend) timeline() []object.Object { return nil }
func (b *liveRegistryBackend) close()                    {}
