package builtin

import (
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

func TestFsHashAndMetadata(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "sample.txt")
	if err := os.WriteFile(file, []byte("hello-forensics"), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	hashResult, errObj := unwrapPair(t, FsHash(stringObj(file), stringObj("sha256")))
	if errObj != nil {
		t.Fatalf("fs_hash error: %s", errObj.Inspect())
	}
	hashPayload, ok := hashResult.(*object.Hash)
	if !ok {
		t.Fatalf("fs_hash payload type: %T", hashResult)
	}
	hashValue := fsfxMustHashString(t, hashPayload, "hash")
	if len(hashValue) != 64 {
		t.Fatalf("sha256 hex length mismatch: %d", len(hashValue))
	}

	metaResult, errObj := unwrapPair(t, FsMetadata(stringObj(file)))
	if errObj != nil {
		t.Fatalf("fs_metadata error: %s", errObj.Inspect())
	}
	metaPayload, ok := metaResult.(*object.Hash)
	if !ok {
		t.Fatalf("fs_metadata payload type: %T", metaResult)
	}
	if fsfxMustHashString(t, metaPayload, "name") != "sample.txt" {
		t.Fatalf("unexpected metadata name")
	}
}

func TestFsWalkAndExtractStrings(t *testing.T) {
	tmp := t.TempDir()
	nestedDir := filepath.Join(tmp, "nested")
	if err := os.MkdirAll(nestedDir, 0755); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "a.txt"), []byte("alpha"), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nestedDir, "b.bin"), []byte{0x00, 'A', 'B', 'C', 'D', 0x00, 'X', 'Y', 'Z'}, 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	walkResult, errObj := unwrapPair(t, FsWalk(stringObj(tmp)))
	if errObj != nil {
		t.Fatalf("fs_walk error: %s", errObj.Inspect())
	}
	walkArr, ok := walkResult.(*object.Array)
	if !ok {
		t.Fatalf("fs_walk payload type: %T", walkResult)
	}
	if len(walkArr.Elements) < 3 {
		t.Fatalf("expected at least 3 walk entries, got %d", len(walkArr.Elements))
	}

	stringsResult, errObj := unwrapPair(t, FsExtractStrings(stringObj(filepath.Join(nestedDir, "b.bin")), intObj(3)))
	if errObj != nil {
		t.Fatalf("fs_extract_strings error: %s", errObj.Inspect())
	}
	stringsArr, ok := stringsResult.(*object.Array)
	if !ok {
		t.Fatalf("fs_extract_strings payload type: %T", stringsResult)
	}
	if len(stringsArr.Elements) < 2 {
		t.Fatalf("expected >=2 extracted strings, got %d", len(stringsArr.Elements))
	}
}

func TestFsMagicDiffCarveEntropy(t *testing.T) {
	tmp := t.TempDir()
	fileA := filepath.Join(tmp, "a.bin")
	fileB := filepath.Join(tmp, "b.bin")

	dataA := []byte{0x50, 0x4B, 0x03, 0x04, 'D', 'A', 'T', 'A', 0x50, 0x4B, 0x03, 0x04}
	dataB := []byte{0x50, 0x4B, 0x03, 0x04, 'D', 'I', 'F', 'F'}
	if err := os.WriteFile(fileA, dataA, 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(fileB, dataB, 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	magicResult, errObj := unwrapPair(t, FsMagic(stringObj(fileA)))
	if errObj != nil {
		t.Fatalf("fs_magic error: %s", errObj.Inspect())
	}
	magicPayload, ok := magicResult.(*object.Hash)
	if !ok {
		t.Fatalf("fs_magic payload type: %T", magicResult)
	}
	if fsfxMustHashString(t, magicPayload, "type") != "zip" {
		t.Fatalf("expected zip magic type")
	}

	diffResult, errObj := unwrapPair(t, FsDiff(stringObj(fileA), stringObj(fileB)))
	if errObj != nil {
		t.Fatalf("fs_diff error: %s", errObj.Inspect())
	}
	diffPayload, ok := diffResult.(*object.Hash)
	if !ok {
		t.Fatalf("fs_diff payload type: %T", diffResult)
	}
	if fsfxMustHashBool(t, diffPayload, "equal") {
		t.Fatalf("expected files to differ")
	}

	carveResult, errObj := unwrapPair(t, FsCarve(stringObj(fileA), stringObj("zip")))
	if errObj != nil {
		t.Fatalf("fs_carve error: %s", errObj.Inspect())
	}
	carveArr, ok := carveResult.(*object.Array)
	if !ok {
		t.Fatalf("fs_carve payload type: %T", carveResult)
	}
	if len(carveArr.Elements) != 2 {
		t.Fatalf("expected 2 carved signatures, got %d", len(carveArr.Elements))
	}

	entropyResult, errObj := unwrapPair(t, FsEntropy(stringObj(fileA)))
	if errObj != nil {
		t.Fatalf("fs_entropy error: %s", errObj.Inspect())
	}
	entropyPayload, ok := entropyResult.(*object.Hash)
	if !ok {
		t.Fatalf("fs_entropy payload type: %T", entropyResult)
	}
	ent := fsfxMustHashFloat(t, entropyPayload, "entropy")
	if ent <= 0 {
		t.Fatalf("expected entropy > 0")
	}
}

func TestDetectMagicSignatures(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"sqlite", []byte("SQLite format 3\x00 the rest"), "sqlite"},
		{"gzip", []byte{0x1F, 0x8B, 0x08}, "gzip"},
		{"jpeg", []byte{0xFF, 0xD8, 0xFF, 0xE0}, "jpeg"},
		{"gif", []byte("GIF89a"), "gif"},
		{"7z", []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "7z"},
		{"elf", []byte{0x7F, 'E', 'L', 'F', 1}, "elf"},
		{"macho64", []byte{0xFE, 0xED, 0xFA, 0xCF}, "macho64"},
		{"ole", []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, "ole"},
		{"evtx", []byte("ElfFile\x00abcd"), "evtx"},
		{"regf", []byte("regf and more"), "regf"},
		{"lnk", []byte{0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00}, "lnk"},
		{"pdf", []byte("%PDF-1.7"), "pdf"},
		{"pe", []byte{0x4D, 0x5A, 0x90}, "pe"},
		{"unknown", []byte{0x00, 0x01, 0x02, 0x03}, "unknown"},
	}
	for _, tc := range cases {
		if typ, _, _ := detectMagic(tc.data); typ != tc.want {
			t.Errorf("%s: detectMagic = %q, want %q", tc.name, typ, tc.want)
		}
	}

	// Offset-based signature (TAR "ustar" at 257).
	tar := make([]byte, 300)
	copy(tar[257:], []byte("ustar"))
	if typ, _, _ := detectMagic(tar); typ != "tar" {
		t.Errorf("tar: got %q, want tar", typ)
	}
	// ISO-BMFF "ftyp" at offset 4.
	mp4 := make([]byte, 16)
	copy(mp4[4:], []byte("ftypisom"))
	if typ, _, _ := detectMagic(mp4); typ != "mp4" {
		t.Errorf("mp4: got %q, want mp4", typ)
	}
	// RIFF container refinement.
	for form, want := range map[string]string{"WAVE": "wav", "AVI ": "avi", "WEBP": "webp"} {
		buf := append([]byte("RIFF\x00\x00\x00\x00"), []byte(form)...)
		if typ, _, _ := detectMagic(buf); typ != want {
			t.Errorf("RIFF %q: got %q, want %q", form, typ, want)
		}
	}
}

func TestFsCarveExpandedType(t *testing.T) {
	// A gzip signature embedded twice in a buffer.
	data := []byte{0x00, 0x00, 0x1F, 0x8B, 0x00, 0x00, 0x00, 0x1F, 0x8B, 0x00}
	path := filepath.Join(t.TempDir(), "blob.bin")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	res, errObj := unwrapPair(t, FsCarve(stringObj(path), stringObj("gzip")))
	if errObj != nil {
		t.Fatalf("fs_carve(gzip) error: %s", errObj.Inspect())
	}
	if arr := res.(*object.Array); len(arr.Elements) != 2 {
		t.Fatalf("gzip carve found %d, want 2", len(arr.Elements))
	}
	// Unsupported type errors (and lists supported types).
	if _, e := unwrapPair(t, FsCarve(stringObj(path), stringObj("definitely-not-a-type"))); e == nil {
		t.Error("expected error for an unsupported carve type")
	}
}

func fsfxMustHashString(t *testing.T, hash *object.Hash, key string) string {
	t.Helper()
	obj := fsfxMustHashValue(t, hash, key)
	s, ok := obj.(*object.String)
	if !ok {
		t.Fatalf("key %s type mismatch: %T", key, obj)
	}
	return s.Value
}

func fsfxMustHashBool(t *testing.T, hash *object.Hash, key string) bool {
	t.Helper()
	obj := fsfxMustHashValue(t, hash, key)
	b, ok := obj.(*object.Boolean)
	if !ok {
		t.Fatalf("key %s type mismatch: %T", key, obj)
	}
	return b.Value
}

func fsfxMustHashFloat(t *testing.T, hash *object.Hash, key string) float64 {
	t.Helper()
	obj := fsfxMustHashValue(t, hash, key)
	f, ok := obj.(*object.Float)
	if !ok {
		t.Fatalf("key %s type mismatch: %T", key, obj)
	}
	return f.Value
}

func fsfxMustHashValue(t *testing.T, hash *object.Hash, key string) object.Object {
	t.Helper()
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		t.Fatalf("missing hash key %q", key)
	}
	return pair.Value
}
