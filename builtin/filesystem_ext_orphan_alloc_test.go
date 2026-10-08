package builtin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// buildExt2DeletedInode is buildExt2Image's volume with a second file, inode
// 13, deleted the way ext2 deletes one: links count zero, a deletion time, its
// bit cleared in the inode bitmap and its block map -- block 9, holding
// "gone\n" -- left in place. blockInUse marks block 9 allocated, as if it had
// since been given to another file.
func buildExt2DeletedInode(blockInUse bool) []byte {
	const bs = 1024
	le := binary.LittleEndian
	img := buildExt2Image("hello.txt", []byte("hi\n"))
	inode := img[5*bs+12*128 : 5*bs+13*128]
	le.PutUint16(inode[0:], 0x81A4) // regular file, 0644
	le.PutUint32(inode[4:], 5)
	le.PutUint32(inode[20:], 1700000000) // dtime
	le.PutUint32(inode[28:], 2)
	le.PutUint32(inode[40:], 9)
	copy(img[9*bs:], "gone\n")
	if blockInUse {
		img[3*bs+1] |= 0x01 // block 9; bit 0 is block 1
	}
	return img
}

// extDeletedRow scans a volume with ext_deleted and returns the handle, the
// index of the row for inode, and the row.
func extDeletedRow(t *testing.T, image []byte, inode int64) (object.Object, int64, *object.Hash) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "deleted.img")
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
	for i, e := range mustHashArrayValue(t, payload.(*object.Hash), "entries") {
		if row := e.(*object.Hash); mustHashIntValue(t, row, "record_id") == inode {
			return handle, int64(i), row
		}
	}
	t.Fatalf("ext_deleted reports no row for inode %d: %s", inode, payload.Inspect())
	return nil, 0, nil
}

func extRecover(t *testing.T, handle object.Object, index int64) *object.Hash {
	t.Helper()
	out := filepath.Join(t.TempDir(), "recovered.bin")
	payload, errObj := unwrapPair(t, ExtRecoverFile(handle, intObj(index), stringObj(out)))
	if errObj != nil {
		t.Fatalf("ext_recover_file: %s", errObj.Inspect())
	}
	return payload.(*object.Hash)
}

func recoveryCaveatsMention(t *testing.T, recovery *object.Hash, text string) bool {
	t.Helper()
	for _, c := range mustHashArrayValue(t, recovery, "caveats") {
		if strings.Contains(c.(*object.String).Value, text) {
			return true
		}
	}
	return false
}

// TestAnOrphanInodeOwnsItsOwnBlocks is M26-FS2-006's regression test. An
// inode on the orphan list was unlinked while open and has not been released:
// the inode bitmap still marks it in use, and every block its map names is
// allocated -- to it. libext grades that partial, and ext_deleted reported it
// reallocated, with ext_recover_file adding that its own bytes were "most
// likely" another file's.
func TestAnOrphanInodeOwnsItsOwnBlocks(t *testing.T) {
	handle, index, row := extDeletedRow(t, buildExt3BrokenOrphanChain(), 12)
	if mustHashStringValue(t, row, "source") != fsDeletedSourceOrphanList {
		t.Fatalf("the fixture's inode 12 is not an orphan-list row: %s", row.Inspect())
	}
	if mustHashBoolValue(t, row, "reallocated") || !mustHashBoolValue(t, row, "allocation_checked") {
		t.Errorf("an orphan's own blocks were reported reallocated: %s", row.Inspect())
	}
	recovery := extRecover(t, handle, index)
	if mustHashBoolValue(t, recovery, "reallocated") ||
		recoveryCaveatsMention(t, recovery, "allocated to a live file") {
		t.Errorf("an orphan's recovery says its bytes are another file's: %s", recovery.Inspect())
	}
}

// A freed inode whose one block is free: checked, and not reallocated.
func TestADeletedExtInodeOverAFreeBlockIsNotReallocated(t *testing.T) {
	_, _, row := extDeletedRow(t, buildExt2DeletedInode(false), 13)
	if mustHashBoolValue(t, row, "reallocated") || !mustHashBoolValue(t, row, "allocation_checked") {
		t.Errorf("a freed inode over a free block: %s", row.Inspect())
	}
}

// A freed inode whose block has been given to something else: reallocated,
// and the recovery names the block.
func TestADeletedExtInodeOverABlockInUseIsReallocated(t *testing.T) {
	handle, index, row := extDeletedRow(t, buildExt2DeletedInode(true), 13)
	if !mustHashBoolValue(t, row, "reallocated") || !mustHashBoolValue(t, row, "allocation_checked") {
		t.Errorf("a freed inode over a block in use: %s", row.Inspect())
	}
	if recovery := extRecover(t, handle, index); !recoveryCaveatsMention(t, recovery, "block 9 of the run is in use") {
		t.Errorf("the recovery does not name the block in use: %s", recovery.Inspect())
	}
}

// TestAnUnreadableExtBlockBitmapIsNotACheck: with the block bitmap past the
// end of the image, no block's allocation can be asked about. libext grades
// that partial too, and it was reported checked and reallocated.
func TestAnUnreadableExtBlockBitmapIsNotACheck(t *testing.T) {
	image := buildExt2DeletedInode(false)
	binary.LittleEndian.PutUint32(image[2*1024:], 1000) // the group's block bitmap
	_, _, row := extDeletedRow(t, image, 13)
	if mustHashBoolValue(t, row, "allocation_checked") || mustHashBoolValue(t, row, "reallocated") {
		t.Errorf("an entry whose bitmap could not be read: %s", row.Inspect())
	}
}
