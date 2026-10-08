package builtin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

func extDeletedScan(t *testing.T, image []byte) *object.Hash {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scan.img")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	payload, errObj := unwrapPair(t, ExtOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("ext_open: %s", errObj.Inspect())
	}
	handle := mustHashValue(t, payload.(*object.Hash), "handle")
	t.Cleanup(func() { ExtClose(handle) })
	payload, errObj = unwrapPair(t, ExtDeleted(handle))
	if errObj != nil {
		t.Fatalf("ext_deleted: %s", errObj.Inspect())
	}
	return payload.(*object.Hash)
}

// TestExtDeletedExaminedIsTheInodeSlotsRead is M26-FS2-018's regression test.
// examined is the scan's denominator, and for ext it was incremented once per
// row returned, so it always equalled entry_count. The fixture's one group
// holds sixteen inodes, the first non-reserved is 11, and the inode-table pass
// reads 11 to 16.
func TestExtDeletedExaminedIsTheInodeSlotsRead(t *testing.T) {
	scan := extDeletedScan(t, buildExt2DeletedInode(false))
	if got := mustHashIntValue(t, scan, "entry_count"); got != 1 {
		t.Fatalf("the fixture's scan returned %d rows, want inode 13's alone: %s", got, scan.Inspect())
	}
	if got := mustHashIntValue(t, scan, "examined"); got != 6 {
		t.Errorf("examined = %d, want the 6 inode-table slots read", got)
	}
}

// TestAnExtInodeTableCutShortByTheImageIsNotComplete: the inode table moved to
// the image's last block, so inodes 1-8 are in it and 9-16 lie past the end.
// libext passes over a slot it cannot read without a warning, so deleted inode
// 13 was simply absent and nothing said a part of the table had not been read.
func TestAnExtInodeTableCutShortByTheImageIsNotComplete(t *testing.T) {
	const bs = 1024
	image := buildExt2DeletedInode(false)
	copy(image[63*bs:64*bs], image[5*bs:6*bs])
	binary.LittleEndian.PutUint32(image[2*bs+8:], 63) // the group's inode table

	scan := extDeletedScan(t, image)
	if mustHashBoolValue(t, scan, "complete") {
		t.Errorf("a scan that could not read 6 inode-table slots says complete: %s", scan.Inspect())
	}
	if reason := mustHashStringValue(t, scan, "incomplete_reason"); !strings.Contains(reason, "past the end of the image") {
		t.Errorf("incomplete_reason does not name the unread slots: %q", reason)
	}
	if got := mustHashIntValue(t, scan, "examined"); got != 0 {
		t.Errorf("examined = %d, want 0: every slot the pass reads lies past the image", got)
	}
}
