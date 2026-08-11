package builtin

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"mutant/object"
)

func regValueByName(t *testing.T, arr *object.Array, name string) *object.Hash {
	t.Helper()
	for _, el := range arr.Elements {
		h := el.(*object.Hash)
		if hStr(t, h, "name") == name {
			return h
		}
	}
	return nil
}

// reg_open on a real regf hive file dispatches to the hive backend.
func TestRegOpenDispatchesHiveFile(t *testing.T) {
	const wantUnix = int64(1700000000)
	filetime := uint64((wantUnix + filetimeEpochDeltaSec) * 10_000_000)
	dir := t.TempDir()
	path := filepath.Join(dir, "NTUSER.DAT")
	if err := os.WriteFile(path, buildTestHive(filetime), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	openPayload, errObj := unwrapPair(t, RegOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("reg_open(hive) error: %s", errObj.Inspect())
	}
	openHash := openPayload.(*object.Hash)
	if hStr(t, openHash, "source_type") != "hive" {
		t.Fatalf("expected source_type=hive, got %q", hStr(t, openHash, "source_type"))
	}
	handle := hStr(t, openHash, "handle")

	keys, errObj := unwrapPair(t, RegEnumKeys(stringObj(handle), stringObj("")))
	if errObj != nil {
		t.Fatalf("reg_enum_keys error: %s", errObj.Inspect())
	}
	ka := keys.(*object.Array)
	if len(ka.Elements) != 1 || ka.Elements[0].(*object.String).Value != "Sub" {
		t.Fatalf("hive subkeys = %s", ka.Inspect())
	}

	vals, errObj := unwrapPair(t, RegEnumValues(stringObj(handle), stringObj("")))
	if errObj != nil {
		t.Fatalf("reg_enum_values error: %s", errObj.Inspect())
	}
	val := regValueByName(t, vals.(*object.Array), "Val")
	if val == nil || hStr(t, val, "type") != "REG_DWORD" || hInt(t, val, "data") != 42 {
		t.Fatalf("hive value Val wrong: %s", vals.Inspect())
	}

	getPayload, errObj := unwrapPair(t, RegGetValue(stringObj(handle), stringObj(""), stringObj("Val")))
	if errObj != nil || hInt(t, getPayload.(*object.Hash), "data") != 42 {
		t.Fatalf("reg_get_value(hive) failed: %v %v", getPayload, errObj)
	}

	_, _ = unwrapPair(t, RegClose(stringObj(handle)))
}

// reg_open on a non-file dispatches to the live Windows registry.
func TestRegOpenDispatchesLiveRegistry(t *testing.T) {
	if runtime.GOOS != "windows" {
		// On non-Windows the live backend must fail honestly.
		if _, errObj := unwrapPair(t, RegOpen(stringObj(`HKLM\SOFTWARE`))); errObj == nil {
			t.Fatal("live registry open should error off Windows")
		}
		return
	}

	openPayload, errObj := unwrapPair(t, RegOpen(stringObj(`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`)))
	if errObj != nil {
		t.Skipf("could not open live registry (permissions?): %s", errObj.Inspect())
	}
	openHash := openPayload.(*object.Hash)
	if hStr(t, openHash, "source_type") != "live" {
		t.Fatalf("expected source_type=live, got %q", hStr(t, openHash, "source_type"))
	}
	handle := hStr(t, openHash, "handle")
	defer RegClose(stringObj(handle))

	// ProductName is a stable REG_SZ value on every Windows install.
	getPayload, errObj := unwrapPair(t, RegGetValue(stringObj(handle), stringObj(""), stringObj("ProductName")))
	if errObj != nil {
		t.Fatalf("reg_get_value(ProductName) error: %s", errObj.Inspect())
	}
	pv := getPayload.(*object.Hash)
	if hStr(t, pv, "type") != "REG_SZ" || !strings.Contains(hStr(t, pv, "data"), "Windows") {
		t.Fatalf("ProductName = %s", pv.Inspect())
	}

	// The key should also enumerate values and (some) subkeys.
	vals, errObj := unwrapPair(t, RegEnumValues(stringObj(handle), stringObj("")))
	if errObj != nil || len(vals.(*object.Array).Elements) == 0 {
		t.Fatalf("reg_enum_values(live) returned nothing: %v", errObj)
	}
	t.Logf("live registry: %d values under CurrentVersion", len(vals.(*object.Array).Elements))
}
