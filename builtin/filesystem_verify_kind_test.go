package builtin

import (
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

// TestAVolumeWithNoIntegrityCheckIsNotVerified is M26-FS1-004's regression
// test, on a real ext2 volume made without metadata checksums. The family's
// own header says such a volume has "nothing to compare", and every *_verify
// summary says a volume with nothing checkable is never verified -- yet the
// superblock plausibility check, a range test that its own detail says is not
// a checksum, made it verified. The same rule made HFS+ verified on its b-tree
// headers and a v4 XFS volume on its clean flag.
func TestAVolumeWithNoIntegrityCheckIsNotVerified(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ext2.img")
	if err := os.WriteFile(path, buildExt2Image("hello.txt", []byte("hi\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	payload, errObj := unwrapPair(t, ExtOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("ext_open: %s", errObj.Inspect())
	}
	handle := mustHashValue(t, payload.(*object.Hash), "handle")
	t.Cleanup(func() { ExtClose(handle) })

	payload, errObj = unwrapPair(t, ExtVerify(handle))
	if errObj != nil {
		t.Fatalf("ext_verify: %s", errObj.Inspect())
	}
	result := payload.(*object.Hash)
	if mustHashBoolValue(t, result, "verified") {
		t.Errorf("an ext2 volume with no metadata checksums verified: %s", result.Inspect())
	}
	if failed := mustHashIntValue(t, result, "checks_failed"); failed != 0 {
		t.Errorf("a healthy volume failed %d checks: %s", failed, result.Inspect())
	}
}
