package builtin

import (
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

func TestMemMapReadAndStrings(t *testing.T) {
	fixture := writeMemFixture(t)

	mapPayload, errObj := unwrapPair(t, MemMap(stringObj(fixture)))
	if errObj != nil {
		t.Fatalf("mem_map error: %s", errObj.Inspect())
	}
	segments, ok := mapPayload.(*object.Array)
	if !ok {
		t.Fatalf("mem_map payload type: %T", mapPayload)
	}
	if len(segments.Elements) == 0 {
		t.Fatalf("expected segments from mem_map")
	}

	readPayload, errObj := unwrapPair(t, MemRead(stringObj(fixture), intObj(0), intObj(8)))
	if errObj != nil {
		t.Fatalf("mem_read error: %s", errObj.Inspect())
	}
	readHash := mfMustHash(t, readPayload)
	if mfMustHashString(t, readHash, "hex") == "" {
		t.Fatalf("expected non-empty mem_read hex")
	}

	stringsPayload, errObj := unwrapPair(t, MemStrings(stringObj(fixture), intObj(5)))
	if errObj != nil {
		t.Fatalf("mem_strings error: %s", errObj.Inspect())
	}
	strArr, ok := stringsPayload.(*object.Array)
	if !ok {
		t.Fatalf("mem_strings payload type: %T", stringsPayload)
	}
	if len(strArr.Elements) == 0 {
		t.Fatalf("expected extracted strings")
	}
}

func TestMemScanFindPEAndShellcode(t *testing.T) {
	fixture := writeMemFixture(t)

	scanPayload, errObj := unwrapPair(t, MemScan(stringObj(fixture), stringObj("MZ")))
	if errObj != nil {
		t.Fatalf("mem_scan error: %s", errObj.Inspect())
	}
	scanHash := mfMustHash(t, scanPayload)
	if mfMustHashInt(t, scanHash, "count") < 1 {
		t.Fatalf("expected at least one scan hit")
	}

	pePayload, errObj := unwrapPair(t, MemFindPE(stringObj(fixture)))
	if errObj != nil {
		t.Fatalf("mem_find_pe error: %s", errObj.Inspect())
	}
	peArr, ok := pePayload.(*object.Array)
	if !ok {
		t.Fatalf("mem_find_pe payload type: %T", pePayload)
	}
	if len(peArr.Elements) < 1 {
		t.Fatalf("expected pe marker hit")
	}

	shellPayload, errObj := unwrapPair(t, MemFindShellcode(stringObj(fixture)))
	if errObj != nil {
		t.Fatalf("mem_find_shellcode error: %s", errObj.Inspect())
	}
	shellArr, ok := shellPayload.(*object.Array)
	if !ok {
		t.Fatalf("mem_find_shellcode payload type: %T", shellPayload)
	}
	if len(shellArr.Elements) < 1 {
		t.Fatalf("expected shellcode signature hit")
	}
}

func TestMemoryBuiltinErrors(t *testing.T) {
	tests := []struct {
		name string
		call func() object.Object
	}{
		{name: "mem_map bad arg", call: func() object.Object { return MemMap(intObj(1)) }},
		{name: "mem_read bad len", call: func() object.Object { return MemRead(stringObj("x"), intObj(0), stringObj("1")) }},
		{name: "mem_scan empty pattern", call: func() object.Object { return MemScan(stringObj("x"), stringObj("")) }},
		{name: "mem_strings bad min", call: func() object.Object { return MemStrings(stringObj("x"), intObj(0)) }},
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

func writeMemFixture(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "memdump.bin")
	data := []byte{
		0x4d, 0x5a, 0x90, 0x00,
		'M', 'e', 'm', 'o', 'r', 'y', '-', 'S', 'n', 'a', 'p', 's', 'h', 'o', 't',
		0x90, 0x90, 0x90,
		0x31, 0xc0, 0x50, 0x68,
		'X', 'Y', 'Z',
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write mem fixture: %v", err)
	}
	return path
}

func mfMustHash(t *testing.T, obj object.Object) *object.Hash {
	t.Helper()
	h, ok := obj.(*object.Hash)
	if !ok {
		t.Fatalf("payload is not HASH: %T", obj)
	}
	return h
}

func mfMustHashValue(t *testing.T, hash *object.Hash, key string) object.Object {
	t.Helper()
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		t.Fatalf("missing key %q", key)
	}
	return pair.Value
}

func mfMustHashString(t *testing.T, hash *object.Hash, key string) string {
	t.Helper()
	obj := mfMustHashValue(t, hash, key)
	s, ok := obj.(*object.String)
	if !ok {
		t.Fatalf("key %s is not STRING: %T", key, obj)
	}
	return s.Value
}

func mfMustHashInt(t *testing.T, hash *object.Hash, key string) int64 {
	t.Helper()
	obj := mfMustHashValue(t, hash, key)
	i, ok := obj.(*object.Integer)
	if !ok {
		t.Fatalf("key %s is not INTEGER: %T", key, obj)
	}
	return i.Value
}
