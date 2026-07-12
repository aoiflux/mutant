package builtin

import (
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
	"strings"
)

func TestRegistryHiveOpenEnumAndGet(t *testing.T) {
	hivePath := writeRegistryFixture(t)

	openResult := RegOpen(stringObj(hivePath))
	openPayload, errObj := unwrapPair(t, openResult)
	if errObj != nil {
		t.Fatalf("reg_open error: %s", errObj.Inspect())
	}
	openHash := regMustHash(t, openPayload)
	handle := regMustHashString(t, openHash, "handle")

	keysResult := RegEnumKeys(stringObj(handle), stringObj(`HKLM\\Software`))
	keysPayload, errObj := unwrapPair(t, keysResult)
	if errObj != nil {
		t.Fatalf("reg_enum_keys error: %s", errObj.Inspect())
	}
	keysArr, ok := keysPayload.(*object.Array)
	if !ok {
		t.Fatalf("reg_enum_keys payload type: %T", keysPayload)
	}
	if len(keysArr.Elements) != 1 {
		t.Fatalf("expected one child key, got=%d", len(keysArr.Elements))
	}

	valuesResult := RegEnumValues(stringObj(handle), stringObj(`HKLM\\Software\\Mutant`))
	valuesPayload, errObj := unwrapPair(t, valuesResult)
	if errObj != nil {
		t.Fatalf("reg_enum_values error: %s", errObj.Inspect())
	}
	valuesArr, ok := valuesPayload.(*object.Array)
	if !ok {
		t.Fatalf("reg_enum_values payload type: %T", valuesPayload)
	}
	if len(valuesArr.Elements) != 2 {
		t.Fatalf("expected two values, got=%d", len(valuesArr.Elements))
	}

	getResult := RegGetValue(stringObj(handle), stringObj(`HKLM\\Software\\Mutant`), stringObj("InstallPath"))
	getPayload, errObj := unwrapPair(t, getResult)
	if errObj != nil {
		t.Fatalf("reg_get_value error: %s", errObj.Inspect())
	}
	getHash := regMustHash(t, getPayload)
	dataObj := regMustHashValue(t, getHash, "data")
	data, ok := dataObj.(*object.String)
	if !ok || data.Value != `C:\\Mutant` {
		t.Fatalf("unexpected reg_get_value data")
	}
}

func TestRegistryDeletedAndTimeline(t *testing.T) {
	hivePath := writeRegistryFixture(t)
	openPayload, errObj := unwrapPair(t, RegOpen(stringObj(hivePath)))
	if errObj != nil {
		t.Fatalf("reg_open error: %s", errObj.Inspect())
	}
	handle := regMustHashString(t, regMustHash(t, openPayload), "handle")

	deletedPayload, errObj := unwrapPair(t, RegDeletedKeys(stringObj(handle)))
	if errObj != nil {
		t.Fatalf("reg_deleted_keys error: %s", errObj.Inspect())
	}
	deletedArr, ok := deletedPayload.(*object.Array)
	if !ok {
		t.Fatalf("reg_deleted_keys payload type: %T", deletedPayload)
	}
	if len(deletedArr.Elements) != 1 {
		t.Fatalf("expected one deleted key")
	}

	timelinePayload, errObj := unwrapPair(t, RegTimeline(stringObj(handle)))
	if errObj != nil {
		t.Fatalf("reg_timeline error: %s", errObj.Inspect())
	}
	timelineArr, ok := timelinePayload.(*object.Array)
	if !ok {
		t.Fatalf("reg_timeline payload type: %T", timelinePayload)
	}
	if len(timelineArr.Elements) != 2 {
		t.Fatalf("expected two timeline events")
	}

	closePayload, errObj := unwrapPair(t, RegClose(stringObj(handle)))
	if errObj != nil {
		t.Fatalf("reg_close error: %s", errObj.Inspect())
	}
	closeHash := regMustHash(t, closePayload)
	if regMustHashString(t, closeHash, "status") != "ok" {
		t.Fatalf("unexpected reg_close status")
	}

	_, errObj = unwrapPair(t, RegEnumKeys(stringObj(handle), stringObj(`HKLM\\Software`)))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown hive handle") {
		t.Fatalf("expected unknown hive handle after close, got: %v", errObj)
	}
}

func TestRegistryArgumentAndLookupErrors(t *testing.T) {
	tests := []struct {
		name string
		call func() object.Object
	}{
		{
			name: "open bad arg type",
			call: func() object.Object { return RegOpen(intObj(1)) },
		},
		{
			name: "enum bad handle",
			call: func() object.Object { return RegEnumKeys(stringObj("missing"), stringObj(`HKLM\\Software`)) },
		},
		{
			name: "get wrong arg count",
			call: func() object.Object { return RegGetValue(stringObj("h"), stringObj(`x`)) },
		},
		{
			name: "close missing handle",
			call: func() object.Object { return RegClose(stringObj("missing")) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errObj := unwrapPair(t, tt.call())
			if errObj == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func writeRegistryFixture(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "offline_hive.json")
	data := `{
  "keys": [
    {
      "path": "HKLM\\Software",
      "last_write": "2026-07-01T00:00:00Z",
      "values": {}
    },
    {
      "path": "HKLM\\Software\\Mutant",
      "last_write": "2026-07-01T01:00:00Z",
      "values": {
        "InstallPath": "C:\\\\Mutant",
        "Enabled": true
      }
    }
  ],
  "deleted_keys": [
    "HKLM\\Software\\OldMutant"
  ],
  "timeline": [
    {"timestamp": "2026-07-01T01:00:00Z", "path": "HKLM\\Software\\Mutant", "action": "create_key"},
    {"timestamp": "2026-07-01T01:10:00Z", "path": "HKLM\\Software\\Mutant", "action": "set_value", "name": "InstallPath"}
  ]
}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("failed writing hive fixture: %v", err)
	}
	return path
}

func regMustHash(t *testing.T, obj object.Object) *object.Hash {
	t.Helper()
	h, ok := obj.(*object.Hash)
	if !ok {
		t.Fatalf("payload is not HASH: %T", obj)
	}
	return h
}

func regMustHashString(t *testing.T, hash *object.Hash, key string) string {
	t.Helper()
	obj := regMustHashValue(t, hash, key)
	str, ok := obj.(*object.String)
	if !ok {
		t.Fatalf("hash key %s is not STRING: %T", key, obj)
	}
	return str.Value
}

func regMustHashValue(t *testing.T, hash *object.Hash, key string) object.Object {
	t.Helper()
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		t.Fatalf("missing key %q", key)
	}
	return pair.Value
}
