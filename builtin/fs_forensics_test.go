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
