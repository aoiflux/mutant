package builtin

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"mutant/object"
)

func TestBinStringsEntropyAndYara(t *testing.T) {
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "sample.bin")
	data := []byte{0x00, 'M', 'A', 'L', 'W', 'A', 'R', 'E', 0x00, 'H', 'E', 'L', 'L', 'O'}
	if err := os.WriteFile(binPath, data, 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	stringsResult, errObj := unwrapPair(t, BinStrings(stringObj(binPath), intObj(4)))
	if errObj != nil {
		t.Fatalf("bin_strings error: %s", errObj.Inspect())
	}
	stringsArr, ok := stringsResult.(*object.Array)
	if !ok || len(stringsArr.Elements) == 0 {
		t.Fatalf("bin_strings payload invalid")
	}

	entropyResult, errObj := unwrapPair(t, BinEntropy(stringObj(binPath)))
	if errObj != nil {
		t.Fatalf("bin_entropy error: %s", errObj.Inspect())
	}
	entropyHash, ok := entropyResult.(*object.Hash)
	if !ok {
		t.Fatalf("bin_entropy payload invalid")
	}
	if mustHashFloatValue(t, entropyHash, "entropy") <= 0 {
		t.Fatalf("expected entropy > 0")
	}

	rules := &object.Array{Elements: []object.Object{stringObj("MALWARE"), stringObj("nomatch")}}
	yaraResult, errObj := unwrapPair(t, BinYaraScan(stringObj(binPath), rules))
	if errObj != nil {
		t.Fatalf("bin_yara_scan error: %s", errObj.Inspect())
	}
	yaraHash, ok := yaraResult.(*object.Hash)
	if !ok {
		t.Fatalf("bin_yara_scan payload invalid")
	}
	matched := mustHashIntValue(t, yaraHash, "matched")
	if matched != 1 {
		t.Fatalf("unexpected matched count: %d", matched)
	}
}

func TestBinaryFormatParsersWithExecutable(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable failed: %v", err)
	}

	switch runtime.GOOS {
	case "windows":
		payload, errObj := unwrapPair(t, BinPEParse(stringObj(exe)))
		if errObj != nil {
			t.Fatalf("bin_pe_parse error: %s", errObj.Inspect())
		}
		peHash, ok := payload.(*object.Hash)
		if !ok || mustHashStringValue(t, peHash, "format") != "pe" {
			t.Fatalf("unexpected PE parse payload")
		}
	case "linux":
		payload, errObj := unwrapPair(t, BinELFParse(stringObj(exe)))
		if errObj != nil {
			t.Fatalf("bin_elf_parse error: %s", errObj.Inspect())
		}
		elfHash, ok := payload.(*object.Hash)
		if !ok || mustHashStringValue(t, elfHash, "format") != "elf" {
			t.Fatalf("unexpected ELF parse payload")
		}
	default:
		t.Skip("parser test only asserted on windows/linux")
	}
}

func TestBinaryImportsSectionsAndDwarf(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable failed: %v", err)
	}

	importsPayload, errObj := unwrapPair(t, BinImports(stringObj(exe)))
	if errObj != nil {
		if runtime.GOOS == "darwin" && strings.Contains(errObj.Message, "unsupported") {
			t.Skip("imports parser not implemented for this format")
		}
		t.Fatalf("bin_imports error: %s", errObj.Inspect())
	}
	importsHash, ok := importsPayload.(*object.Hash)
	if !ok {
		t.Fatalf("bin_imports payload invalid")
	}
	importsObj := mustHashValue(t, importsHash, "imports")
	if _, ok := importsObj.(*object.Array); !ok {
		t.Fatalf("imports field is not ARRAY")
	}

	sectionsPayload, errObj := unwrapPair(t, BinSections(stringObj(exe)))
	if errObj != nil {
		if runtime.GOOS == "darwin" && strings.Contains(errObj.Message, "unsupported") {
			t.Skip("sections parser not implemented for this format")
		}
		t.Fatalf("bin_sections error: %s", errObj.Inspect())
	}
	sectionsHash, ok := sectionsPayload.(*object.Hash)
	if !ok {
		t.Fatalf("bin_sections payload invalid")
	}
	sectionsObj := mustHashValue(t, sectionsHash, "sections")
	if _, ok := sectionsObj.(*object.Array); !ok {
		t.Fatalf("sections field is not ARRAY")
	}

	dwarfPayload, errObj := unwrapPair(t, BinDWARFParse(stringObj(exe)))
	if errObj != nil {
		t.Skipf("dwarf may be unavailable in this test binary: %s", errObj.Message)
	}
	dwarfHash, ok := dwarfPayload.(*object.Hash)
	if !ok {
		t.Fatalf("bin_dwarf_parse payload invalid")
	}
	if mustHashIntValue(t, dwarfHash, "compile_units") < 0 {
		t.Fatalf("unexpected compile_units")
	}
}

func mustHashValue(t *testing.T, hash *object.Hash, key string) object.Object {
	t.Helper()
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		t.Fatalf("missing hash key %q", key)
	}
	return pair.Value
}

func mustHashStringValue(t *testing.T, hash *object.Hash, key string) string {
	t.Helper()
	obj := mustHashValue(t, hash, key)
	value, ok := obj.(*object.String)
	if !ok {
		t.Fatalf("key %s is not STRING", key)
	}
	return value.Value
}

func mustHashIntValue(t *testing.T, hash *object.Hash, key string) int64 {
	t.Helper()
	obj := mustHashValue(t, hash, key)
	value, ok := obj.(*object.Integer)
	if !ok {
		t.Fatalf("key %s is not INTEGER", key)
	}
	return value.Value
}

func mustHashFloatValue(t *testing.T, hash *object.Hash, key string) float64 {
	t.Helper()
	obj := mustHashValue(t, hash, key)
	value, ok := obj.(*object.Float)
	if !ok {
		t.Fatalf("key %s is not FLOAT", key)
	}
	return value.Value
}
