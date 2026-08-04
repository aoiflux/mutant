package builtin

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"mutant/object"
)

func pfPutUTF16(dst []byte, s string) {
	for i, c := range utf16.Encode([]rune(s)) {
		binary.LittleEndian.PutUint16(dst[i*2:], c)
	}
}

func pfEncodeUTF16ZList(list []string) []byte {
	out := []byte{}
	for _, s := range list {
		u := utf16.Encode([]rune(s))
		b := make([]byte, len(u)*2+2)
		for i, c := range u {
			binary.LittleEndian.PutUint16(b[i*2:], c)
		}
		out = append(out, b...)
	}
	return out
}

// buildSCCAv30 crafts a minimal but valid Win10 (v30) uncompressed prefetch.
// Must stay byte-identical to the generator that produced pfMAMVectorBase64.
func buildSCCAv30() []byte {
	buf := make([]byte, 0x300)
	binary.LittleEndian.PutUint32(buf[0:], 30)
	copy(buf[4:8], "SCCA")
	binary.LittleEndian.PutUint32(buf[8:], 0x11)
	pfPutUTF16(buf[0x10:0x4C], "CALC.EXE")
	binary.LittleEndian.PutUint32(buf[0x4C:], 0xDEADBEEF)

	files := []string{`\VOLUME\WINDOWS\SYSTEM32\CALC.EXE`, `\VOLUME\WINDOWS\SYSTEM32\KERNEL32.DLL`}
	fnBlob := pfEncodeUTF16ZList(files)
	fnOff := 0x100
	copy(buf[fnOff:], fnBlob)
	binary.LittleEndian.PutUint32(buf[0x64:], uint32(fnOff))
	binary.LittleEndian.PutUint32(buf[0x68:], uint32(len(fnBlob)))

	ft := uint64((int64(1600000000) + filetimeEpochDeltaSec) * 10_000_000)
	binary.LittleEndian.PutUint64(buf[0x80:], ft)
	binary.LittleEndian.PutUint32(buf[0xD0:], 7)

	volOff := 0x200
	binary.LittleEndian.PutUint32(buf[0x6C:], uint32(volOff))
	binary.LittleEndian.PutUint32(buf[0x70:], 1)
	devPath := `\DEVICE\HARDDISKVOLUME2`
	devPathOff := 96
	binary.LittleEndian.PutUint32(buf[volOff+0x00:], uint32(devPathOff))
	binary.LittleEndian.PutUint32(buf[volOff+0x04:], uint32(len(devPath)))
	binary.LittleEndian.PutUint64(buf[volOff+0x08:], ft)
	binary.LittleEndian.PutUint32(buf[volOff+0x10:], 0x12345678)
	pfPutUTF16(buf[volOff+devPathOff:], devPath)

	binary.LittleEndian.PutUint32(buf[0x0C:], uint32(len(buf)))
	return buf
}

// pfMAMVectorBase64 is buildSCCAv30() compressed with the Windows Xpress-Huffman
// engine (ntdll RtlCompressBuffer) and wrapped in a MAM\x04 container — real
// Win10-format compressed prefetch, generated once so the decompress+parse path
// is covered on every platform.
const pfMAMVectorBase64 = `TUFNBAADAABzdwBwAAAAAHAHAHAAAAAHcAAAAAAAAAYAdgcAAAAAAGBQVgBncGZ3AFZ3ZncABQAHAAAAAAAAAAAAAAAHAAAABwAAAHAAAAAHAAAAAAAAAAAAAAcAAHAAAAAAAAAAAAcAAAAAcAAAAAAAAAcAAAAHAAAAAAAAAHAAAAAAAAAAAAdwAAAAcABQBwAAAAAAAAAFAAAAAAAAAGYHAAAAAAAAdQBwAAAABgcFAAAAAAAHAAAAAAAAAABwBQAAAAAAAAB1AAcAcAAAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALYIMYn1rIADARTCAs6pjMsR3nYaHzSASpxr7lXp+nPZrn6dHugVHAQmMUgOljMTQRw3IEpDGEnqlEEZBmOSRFaHLlRUfJEEEwAgNdKrkIK3bnGxh9IZnFpgiP4l0T7rB3GiZTKCtJkGHH3TvtToqI/QjOeP+0454gCAUgAA`

func pfArr(t *testing.T, h *object.Hash, key string) *object.Array {
	t.Helper()
	a, ok := hashValueByKey(h, key).(*object.Array)
	if !ok {
		t.Fatalf("key %q not an ARRAY", key)
	}
	return a
}

func assertPrefetchFields(t *testing.T, h *object.Hash, wantCompressed bool) {
	t.Helper()
	if got := hInt(t, h, "version"); got != 30 {
		t.Errorf("version = %d, want 30", got)
	}
	if got := hStr(t, h, "executable"); got != "CALC.EXE" {
		t.Errorf("executable = %q, want CALC.EXE", got)
	}
	if got := hStr(t, h, "prefetch_hash"); got != "DEADBEEF" {
		t.Errorf("prefetch_hash = %q, want DEADBEEF", got)
	}
	if got := hInt(t, h, "run_count"); got != 7 {
		t.Errorf("run_count = %d, want 7", got)
	}
	if got := hBoolAt(t, h, "compressed"); got != wantCompressed {
		t.Errorf("compressed = %v, want %v", got, wantCompressed)
	}

	rt := pfArr(t, h, "run_times")
	if len(rt.Elements) != 1 {
		t.Fatalf("run_times len = %d, want 1", len(rt.Elements))
	}
	if got := rt.Elements[0].(*object.String).Value; got != unixToISO(1600000000) {
		t.Errorf("run_times[0] = %q, want %q", got, unixToISO(1600000000))
	}

	files := pfArr(t, h, "files_loaded")
	if len(files.Elements) != 2 {
		t.Fatalf("files_loaded len = %d, want 2", len(files.Elements))
	}
	if got := files.Elements[0].(*object.String).Value; got != `\VOLUME\WINDOWS\SYSTEM32\CALC.EXE` {
		t.Errorf("files_loaded[0] = %q", got)
	}
	if got := files.Elements[1].(*object.String).Value; got != `\VOLUME\WINDOWS\SYSTEM32\KERNEL32.DLL` {
		t.Errorf("files_loaded[1] = %q", got)
	}
	if got := hInt(t, h, "file_count"); got != 2 {
		t.Errorf("file_count = %d, want 2", got)
	}

	vols := pfArr(t, h, "volumes")
	if len(vols.Elements) != 1 {
		t.Fatalf("volumes len = %d, want 1", len(vols.Elements))
	}
	v0 := vols.Elements[0].(*object.Hash)
	if got := hStr(t, v0, "device_path"); got != `\DEVICE\HARDDISKVOLUME2` {
		t.Errorf("volume device_path = %q", got)
	}
	if got := hStr(t, v0, "serial"); got != "12345678" {
		t.Errorf("volume serial = %q, want 12345678", got)
	}
}

func TestPrefetchParseUncompressed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "CALC.EXE-DEADBEEF.pf")
	if err := os.WriteFile(path, buildSCCAv30(), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	payload, errObj := unwrapPair(t, PrefetchParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("prefetch_parse error: %s", errObj.Inspect())
	}
	assertPrefetchFields(t, payload.(*object.Hash), false)
}

func TestPrefetchParseCompressedVector(t *testing.T) {
	mam, err := base64.StdEncoding.DecodeString(pfMAMVectorBase64)
	if err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	if string(mam[0:3]) != "MAM" {
		t.Fatalf("vector is not a MAM container")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "CALC.EXE-COMPRESSED.pf")
	if err := os.WriteFile(path, mam, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	payload, errObj := unwrapPair(t, PrefetchParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("prefetch_parse (compressed) error: %s", errObj.Inspect())
	}
	assertPrefetchFields(t, payload.(*object.Hash), true)
}

func TestPrefetchParseRejectsNonPrefetch(t *testing.T) {
	dir := t.TempDir()
	// Not an SCCA file.
	bad := filepath.Join(dir, "bad.pf")
	_ = os.WriteFile(bad, []byte("this is definitely not a prefetch file at all"), 0644)
	if _, errObj := unwrapPair(t, PrefetchParse(stringObj(bad))); errObj == nil {
		t.Error("expected error for non-SCCA file")
	}
	// Too short.
	short := filepath.Join(dir, "short.pf")
	_ = os.WriteFile(short, []byte("SCCA"), 0644)
	if _, errObj := unwrapPair(t, PrefetchParse(stringObj(short))); errObj == nil {
		t.Error("expected error for truncated file")
	}
}
