package builtin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

// machoThin64 crafts a minimal 64-bit thin Mach-O header (little-endian,
// ncmds=0) that debug/macho parses into a valid File.
func machoThin64(cpuType, cpuSubtype uint32) []byte {
	h := make([]byte, 32)
	binary.LittleEndian.PutUint32(h[0:], 0xFEEDFACF) // MH_MAGIC_64
	binary.LittleEndian.PutUint32(h[4:], cpuType)
	binary.LittleEndian.PutUint32(h[8:], cpuSubtype)
	binary.LittleEndian.PutUint32(h[12:], 2) // MH_EXECUTE
	binary.LittleEndian.PutUint32(h[16:], 0) // ncmds
	binary.LittleEndian.PutUint32(h[20:], 0) // sizeofcmds
	binary.LittleEndian.PutUint32(h[24:], 0) // flags
	binary.LittleEndian.PutUint32(h[28:], 0) // reserved
	return h
}

type machoArch struct {
	cpuType, cpuSubtype uint32
	thin                []byte
}

// machoFat wraps thin images in a fat/universal container (big-endian header).
func machoFat(arches []machoArch) []byte {
	n := len(arches)
	buf := make([]byte, 8+20*n)
	binary.BigEndian.PutUint32(buf[0:], 0xCAFEBABE) // FAT_MAGIC
	binary.BigEndian.PutUint32(buf[4:], uint32(n))
	offset := 8 + 20*n
	images := []byte{}
	for i, a := range arches {
		base := 8 + 20*i
		binary.BigEndian.PutUint32(buf[base+0:], a.cpuType)
		binary.BigEndian.PutUint32(buf[base+4:], a.cpuSubtype)
		binary.BigEndian.PutUint32(buf[base+8:], uint32(offset))
		binary.BigEndian.PutUint32(buf[base+12:], uint32(len(a.thin)))
		binary.BigEndian.PutUint32(buf[base+16:], 12) // 2^12 alignment
		images = append(images, a.thin...)
		offset += len(a.thin)
	}
	return append(buf, images...)
}

const (
	cpuTypeAmd64 = 0x01000007
	cpuTypeArm64 = 0x0100000C
)

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestBinMachoParseThin(t *testing.T) {
	path := writeTemp(t, "thin", machoThin64(cpuTypeAmd64, 3))
	payload, errObj := unwrapPair(t, BinMachOParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("bin_macho_parse error: %s", errObj.Inspect())
	}
	h := payload.(*object.Hash)

	if got := hStr(t, h, "format"); got != "macho" {
		t.Errorf("format = %q", got)
	}
	if hBoolAt(t, h, "fat") {
		t.Error("thin binary should have fat=false")
	}
	if got := hInt(t, h, "magic"); got != 0xFEEDFACF {
		t.Errorf("magic = %#x, want 0xFEEDFACF", got)
	}
	if got := hStr(t, h, "cpu"); got != "CpuAmd64" {
		t.Errorf("cpu = %q, want CpuAmd64", got)
	}
	if got := hStr(t, h, "type"); got != "Exec" {
		t.Errorf("type = %q, want Exec", got)
	}
	if got := hInt(t, h, "num_sections"); got != 0 {
		t.Errorf("num_sections = %d, want 0", got)
	}
	if _, ok := hashValueByKey(h, "imported_libraries").(*object.Array); !ok {
		t.Error("imported_libraries should be an array")
	}
}

func TestBinMachoParseFat(t *testing.T) {
	fat := machoFat([]machoArch{
		{cpuTypeAmd64, 3, machoThin64(cpuTypeAmd64, 3)},
		{cpuTypeArm64, 0, machoThin64(cpuTypeArm64, 0)},
	})
	path := writeTemp(t, "fat", fat)
	payload, errObj := unwrapPair(t, BinMachOParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("bin_macho_parse (fat) error: %s", errObj.Inspect())
	}
	h := payload.(*object.Hash)

	if !hBoolAt(t, h, "fat") {
		t.Error("fat binary should have fat=true")
	}
	if got := hInt(t, h, "num_arches"); got != 2 {
		t.Fatalf("num_arches = %d, want 2", got)
	}
	arches := hashValueByKey(h, "architectures").(*object.Array)
	if got := hStr(t, arches.Elements[0].(*object.Hash), "cpu"); got != "CpuAmd64" {
		t.Errorf("arch[0].cpu = %q, want CpuAmd64", got)
	}
	if got := hStr(t, arches.Elements[1].(*object.Hash), "cpu"); got != "CpuArm64" {
		t.Errorf("arch[1].cpu = %q, want CpuArm64", got)
	}
}

func TestBinMachoParseRejectsNonMacho(t *testing.T) {
	path := writeTemp(t, "notmacho", []byte("this is not a mach-o binary at all!!"))
	if _, errObj := unwrapPair(t, BinMachOParse(stringObj(path))); errObj == nil {
		t.Error("expected error for a non-Mach-O file")
	}
}
