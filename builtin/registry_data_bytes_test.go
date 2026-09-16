package builtin

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"

	"mutant/object"
)

// A byte range no text codec would survive: a PE magic, a NUL, and a lone 0xFF
// that is not a legal UTF-8 lead byte.
var binaryValue = []byte{0x4D, 0x5A, 0x90, 0x00, 0xFF, 0xFE, 0x00, 0x01}

// hiveWithValues writes a one-key regf hive holding the given values and returns
// its path. The builder emits referenced (out-of-line) data cells, which is the
// case that matters here: those alias the hive buffer the handle keeps open.
func hiveWithValues(t *testing.T, values ...hiveKV) string {
	t.Helper()

	root := &hiveNode{name: "CMI-CreateHive", values: values}
	path := filepath.Join(t.TempDir(), "TEST.hive")
	if err := os.WriteFile(path, newHiveBuilder(0).finish(root), 0644); err != nil {
		t.Fatalf("write hive: %v", err)
	}
	return path
}

func openHive(t *testing.T, path string) string {
	t.Helper()

	payload, errObj := unwrapPair(t, HiveOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("hive_open: %s", errObj.Inspect())
	}
	return regMustHashString(t, regMustHash(t, payload), "handle")
}

// optionalRegField reports a key's value and whether the key is there at all, which is
// the distinction these tests are about: data_bytes is present exactly when data
// is hex, so its absence is part of the contract rather than an omission.
func optionalRegField(hash *object.Hash, key string) (object.Object, bool) {
	pair, ok := hash.Pairs[(&object.String{Value: key}).HashKey()]
	if !ok {
		return nil, false
	}
	return pair.Value, true
}

func mustDataBytes(t *testing.T, hash *object.Hash) *object.Bytes {
	t.Helper()

	field, present := optionalRegField(hash, "data_bytes")
	if !present {
		t.Fatalf("no data_bytes on %s", hash.Inspect())
	}
	buf, ok := field.(*object.Bytes)
	if !ok {
		t.Fatalf("data_bytes is %s, want BYTES", field.Type())
	}
	return buf
}

// The pair cannot drift: data_bytes and the hex in data are two renderings of
// one buffer, so hex(data_bytes) has to reproduce data exactly.
func TestHiveBinaryValueCarriesDataBytes(t *testing.T) {
	if utf8.Valid(binaryValue) {
		t.Fatal("the fixture is valid UTF-8; it cannot exercise the binary case")
	}

	handle := openHive(t, hiveWithValues(t, hiveKV{name: "Blob", bin: binaryValue, isBin: true}))

	payload, errObj := unwrapPair(t, HiveGetValue(stringObj(handle), stringObj(""), stringObj("Blob")))
	if errObj != nil {
		t.Fatalf("hive_get_value: %s", errObj.Inspect())
	}
	value := regMustHash(t, payload)

	if got := regMustHashString(t, value, "type"); got != "REG_BINARY" {
		t.Fatalf("type = %q, want REG_BINARY", got)
	}
	buf := mustDataBytes(t, value)
	if !bytes.Equal(buf.Value, binaryValue) {
		t.Errorf("data_bytes = %x, want %x", buf.Value, binaryValue)
	}
	if got, want := hex.EncodeToString(buf.Value), regMustHashString(t, value, "data"); got != want {
		t.Errorf("hex(data_bytes) = %s, but data = %s", got, want)
	}
}

// hive_list_values builds its own hash; it has to agree with hive_get_value.
func TestHiveListValuesCarriesDataBytes(t *testing.T) {
	handle := openHive(t, hiveWithValues(t, hiveKV{name: "Blob", bin: binaryValue, isBin: true}))

	payload, errObj := unwrapPair(t, HiveListValues(stringObj(handle)))
	if errObj != nil {
		t.Fatalf("hive_list_values: %s", errObj.Inspect())
	}
	values := payload.(*object.Array)
	if len(values.Elements) != 1 {
		t.Fatalf("got %d values, want 1", len(values.Elements))
	}

	if buf := mustDataBytes(t, values.Elements[0].(*object.Hash)); !bytes.Equal(buf.Value, binaryValue) {
		t.Errorf("data_bytes = %x, want %x", buf.Value, binaryValue)
	}
}

// A REG_SZ is already a String and a REG_DWORD already an Integer, so there is
// no hex to undo and nothing for data_bytes to add. Emitting an empty buffer
// instead would be indistinguishable from a REG_BINARY that really is empty.
func TestNonBinaryValuesOmitDataBytes(t *testing.T) {
	handle := openHive(t,
		hiveWithValues(t,
			hiveKV{name: "Path", str: `C:\Mutant`},
			hiveKV{name: "Count", dword: 42, isDword: true},
		))

	payload, errObj := unwrapPair(t, HiveListValues(stringObj(handle)))
	if errObj != nil {
		t.Fatalf("hive_list_values: %s", errObj.Inspect())
	}

	for _, element := range payload.(*object.Array).Elements {
		value := element.(*object.Hash)
		if _, present := optionalRegField(value, "data_bytes"); present {
			t.Errorf("%s value carries data_bytes: %s",
				regMustHashString(t, value, "type"), value.Inspect())
		}
	}
}

// The reg_* front end reaches the same hive through registryBackend, so the
// field has to survive that indirection rather than only the direct readers.
func TestRegGetValueCarriesDataBytesOnAHiveSource(t *testing.T) {
	path := hiveWithValues(t, hiveKV{name: "Blob", bin: binaryValue, isBin: true})

	payload, errObj := unwrapPair(t, RegOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("reg_open: %s", errObj.Inspect())
	}
	handle := regMustHashString(t, regMustHash(t, payload), "handle")

	payload, errObj = unwrapPair(t, RegGetValue(stringObj(handle), stringObj(""), stringObj("Blob")))
	if errObj != nil {
		t.Fatalf("reg_get_value: %s", errObj.Inspect())
	}
	if buf := mustDataBytes(t, regMustHash(t, payload)); !bytes.Equal(buf.Value, binaryValue) {
		t.Errorf("data_bytes = %x, want %x", buf.Value, binaryValue)
	}
}

// A hive-JSON file is a transcription of a hive, not the artifact: its value
// types come from JSON, and registryTypeName has no case that yields
// REG_BINARY. There are no stored bytes to report, and encoding a JSON string
// as UTF-16LE to fill the field would hand back bytes that were never on a disk.
func TestJSONRegistrySourceNeverReportsDataBytes(t *testing.T) {
	payload, errObj := unwrapPair(t, RegOpen(stringObj(writeRegistryFixture(t))))
	if errObj != nil {
		t.Fatalf("reg_open: %s", errObj.Inspect())
	}
	handle := regMustHashString(t, regMustHash(t, payload), "handle")

	payload, errObj = unwrapPair(t, RegEnumValues(stringObj(handle), stringObj(`HKLM\Software\Mutant`)))
	if errObj != nil {
		t.Fatalf("reg_enum_values: %s", errObj.Inspect())
	}
	values := payload.(*object.Array)
	if len(values.Elements) == 0 {
		t.Fatal("the JSON fixture reported no values; the test proves nothing")
	}

	for _, element := range values.Elements {
		value := element.(*object.Hash)
		if _, present := optionalRegField(value, "data_bytes"); present {
			t.Errorf("JSON source reported data_bytes: %s", value.Inspect())
		}
	}
}

// A *object.Bytes is mutable from a script -- b[0] = 0 is a statement -- and the
// hive stays open behind its handle, so a returned view of the hive buffer would
// let one assignment rewrite what every later read parses. This is the guard for
// the clone in valueData; delete it and the second read below comes back
// modified.
func TestHiveDataBytesDoesNotAliasTheHive(t *testing.T) {
	handle := openHive(t, hiveWithValues(t, hiveKV{name: "Blob", bin: binaryValue, isBin: true}))

	read := func() *object.Bytes {
		t.Helper()
		payload, errObj := unwrapPair(t, HiveGetValue(stringObj(handle), stringObj(""), stringObj("Blob")))
		if errObj != nil {
			t.Fatalf("hive_get_value: %s", errObj.Inspect())
		}
		return mustDataBytes(t, regMustHash(t, payload))
	}

	first := read()
	first.Value[0] = 0x00

	if second := read(); !bytes.Equal(second.Value, binaryValue) {
		t.Errorf("a second read returned %x after the first was mutated, want %x",
			second.Value, binaryValue)
	}
}
