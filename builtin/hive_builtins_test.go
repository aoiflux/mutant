package builtin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

// makeNK builds the data bytes of an nk (key) record.
func makeNK(name string, filetime uint64, subCount, subListRel, valCount, valListRel uint32) []byte {
	nameBytes := []byte(name)
	d := make([]byte, 0x4C+len(nameBytes))
	copy(d[0:2], "nk")
	binary.LittleEndian.PutUint16(d[0x02:0x04], 0x0020) // KEY_COMP_NAME (ASCII name)
	binary.LittleEndian.PutUint64(d[0x04:0x0C], filetime)
	binary.LittleEndian.PutUint32(d[0x14:0x18], subCount)
	binary.LittleEndian.PutUint32(d[0x1C:0x20], subListRel)
	binary.LittleEndian.PutUint32(d[0x24:0x28], valCount)
	binary.LittleEndian.PutUint32(d[0x28:0x2C], valListRel)
	binary.LittleEndian.PutUint32(d[0x2C:0x30], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(d[0x30:0x34], 0xFFFFFFFF)
	binary.LittleEndian.PutUint16(d[0x48:0x4A], uint16(len(nameBytes)))
	copy(d[0x4C:], nameBytes)
	return d
}

// makeVKDword builds a vk (value) record for an inline REG_DWORD.
func makeVKDword(name string, value uint32) []byte {
	nameBytes := []byte(name)
	d := make([]byte, 0x14+len(nameBytes))
	copy(d[0:2], "vk")
	binary.LittleEndian.PutUint16(d[0x02:0x04], uint16(len(nameBytes)))
	binary.LittleEndian.PutUint32(d[0x04:0x08], 0x80000004) // inline flag | size 4
	binary.LittleEndian.PutUint32(d[0x08:0x0C], value)      // inline data
	binary.LittleEndian.PutUint32(d[0x0C:0x10], 4)          // REG_DWORD
	binary.LittleEndian.PutUint16(d[0x10:0x12], 0x0001)     // ASCII name
	copy(d[0x14:], nameBytes)
	return d
}

func buildTestHive(filetime uint64) []byte {
	buf := make([]byte, 0x2000)
	copy(buf[0:4], "regf")
	binary.LittleEndian.PutUint32(buf[0x24:0x28], 0x20) // root cell at rel 0x20
	copy(buf[0x1000:0x1004], "hbin")

	putCell := func(rel uint32, data []byte) {
		total := len(data) + 4
		if total%8 != 0 {
			total += 8 - total%8
		}
		abs := 0x1000 + int(rel)
		binary.LittleEndian.PutUint32(buf[abs:abs+4], uint32(int32(-total))) // negative => allocated
		copy(buf[abs+4:abs+4+len(data)], data)
	}

	// Root "ROOT": 1 subkey (list @0xD0), 1 value (list @0xE0).
	putCell(0x20, makeNK("ROOT", filetime, 1, 0xD0, 1, 0xE0))
	// Subkey "Sub": no subkeys, no values.
	putCell(0x78, makeNK("Sub", 0, 0, 0xFFFFFFFF, 0, 0xFFFFFFFF))
	// lf subkey list for root: 1 entry -> Sub @0x78.
	lf := make([]byte, 12)
	copy(lf[0:2], "lf")
	binary.LittleEndian.PutUint16(lf[2:4], 1)
	binary.LittleEndian.PutUint32(lf[4:8], 0x78)
	putCell(0xD0, lf)
	// value list for root: 1 vk offset -> Val @0xE8.
	vlist := make([]byte, 4)
	binary.LittleEndian.PutUint32(vlist[0:4], 0xE8)
	putCell(0xE0, vlist)
	// vk value "Val" = REG_DWORD 42.
	putCell(0xE8, makeVKDword("Val", 42))
	return buf
}

func TestHiveParse(t *testing.T) {
	const wantUnix = int64(1700000000)
	filetime := uint64((wantUnix + filetimeEpochDeltaSec) * 10_000_000)

	dir := t.TempDir()
	path := filepath.Join(dir, "TEST.hive")
	if err := os.WriteFile(path, buildTestHive(filetime), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	openPayload, errObj := unwrapPair(t, HiveOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("hive_open error: %s", errObj.Inspect())
	}
	handle := openPayload.(*object.Hash).Pairs[(&object.String{Value: "handle"}).HashKey()].Value.(*object.String).Value

	// key info on the root.
	infoPayload, errObj := unwrapPair(t, HiveKeyInfo(stringObj(handle)))
	if errObj != nil {
		t.Fatalf("hive_key_info error: %s", errObj.Inspect())
	}
	info := infoPayload.(*object.Hash)
	if hStr(t, info, "name") != "ROOT" {
		t.Fatalf("root name = %q", hStr(t, info, "name"))
	}
	if hInt(t, info, "last_write") != wantUnix {
		t.Fatalf("last_write = %d, want %d", hInt(t, info, "last_write"), wantUnix)
	}
	if hInt(t, info, "subkey_count") != 1 || hInt(t, info, "value_count") != 1 {
		t.Fatalf("counts: %s", info.Inspect())
	}

	// list subkeys.
	keysPayload, errObj := unwrapPair(t, HiveListKeys(stringObj(handle)))
	if errObj != nil {
		t.Fatalf("hive_list_keys error: %s", errObj.Inspect())
	}
	keys := keysPayload.(*object.Array)
	if len(keys.Elements) != 1 || keys.Elements[0].(*object.String).Value != "Sub" {
		t.Fatalf("subkeys = %s", keys.Inspect())
	}

	// list values.
	valsPayload, errObj := unwrapPair(t, HiveListValues(stringObj(handle)))
	if errObj != nil {
		t.Fatalf("hive_list_values error: %s", errObj.Inspect())
	}
	vals := valsPayload.(*object.Array)
	if len(vals.Elements) != 1 {
		t.Fatalf("values = %s", vals.Inspect())
	}
	v := vals.Elements[0].(*object.Hash)
	if hStr(t, v, "name") != "Val" || hStr(t, v, "type") != "REG_DWORD" || hInt(t, v, "data") != 42 {
		t.Fatalf("value = %s", v.Inspect())
	}

	// get a single value + navigate into the subkey.
	getPayload, errObj := unwrapPair(t, HiveGetValue(stringObj(handle), stringObj(""), stringObj("Val")))
	if errObj != nil || hInt(t, getPayload.(*object.Hash), "data") != 42 {
		t.Fatalf("hive_get_value: %v %v", getPayload, errObj)
	}
	subKeys, errObj := unwrapPair(t, HiveListKeys(stringObj(handle), stringObj("Sub")))
	if errObj != nil {
		t.Fatalf("hive_list_keys(Sub) error: %s", errObj.Inspect())
	}
	if len(subKeys.(*object.Array).Elements) != 0 {
		t.Fatal("Sub should have no subkeys")
	}

	// close + errors.
	if _, errObj := unwrapPair(t, HiveClose(stringObj(handle))); errObj != nil {
		t.Fatalf("hive_close error: %s", errObj.Inspect())
	}
	if _, errObj := unwrapPair(t, HiveListKeys(stringObj(handle))); errObj == nil {
		t.Fatal("listing keys after close should error")
	}

	// a non-hive file errors.
	bad := filepath.Join(dir, "bad.bin")
	_ = os.WriteFile(bad, []byte("not a hive"), 0644)
	if _, errObj := unwrapPair(t, HiveOpen(stringObj(bad))); errObj == nil {
		t.Fatal("hive_open of a non-hive should error")
	}
}
