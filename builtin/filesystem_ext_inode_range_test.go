package builtin

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

// journalBlockCopy gives buildExt3BrokenOrphanChain's journal one committed
// transaction: a descriptor in journal block 1 tagging fsBlock, the block's
// copy in journal block 2 and a commit in journal block 3. JBD2 is big-endian,
// and without the 64bit or csum features a tag is eight bytes: the block
// number, a checksum word and the flags.
func journalBlockCopy(img []byte, fsBlock uint32) []byte {
	const bs = 1024
	be := binary.BigEndian
	descriptor := img[17*bs : 18*bs]
	be.PutUint32(descriptor[0:], 0xC03B3998)
	be.PutUint32(descriptor[4:], 1) // descriptor block
	be.PutUint32(descriptor[8:], 1) // transaction sequence
	be.PutUint32(descriptor[12:], fsBlock)
	be.PutUint16(descriptor[18:], 0x8|0x2) // last tag, same UUID
	copy(img[18*bs:19*bs], img[int(fsBlock)*bs:int(fsBlock+1)*bs])
	commit := img[19*bs : 20*bs]
	be.PutUint32(commit[0:], 0xC03B3998)
	be.PutUint32(commit[4:], 2) // commit block
	be.PutUint32(commit[8:], 1)
	be.PutUint64(commit[48:], 1700000000) // commit time
	return img
}

// TestAnExtInodeNumberPastTheVolumeIsRefused is M26-FS2-007's regression
// test. libext takes an inode number as a uint32 and both builtins accepted
// any positive integer, so 4294967308 narrowed to 12: inode 12's journalled
// versions came back under 4294967308, and its bytes were recovered as that
// inode's. The fixture's sixteen inodes put 17 past the end as well.
func TestAnExtInodeNumberPastTheVolumeIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journalled.img")
	if err := os.WriteFile(path, journalBlockCopy(buildExt3BrokenOrphanChain(), 6), 0o600); err != nil {
		t.Fatal(err)
	}
	payload, errObj := unwrapPair(t, ExtOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("ext_open: %s", errObj.Inspect())
	}
	handle := mustHashValue(t, payload.(*object.Hash), "handle")
	t.Cleanup(func() { ExtClose(handle) })

	payload, errObj = unwrapPair(t, ExtInodeVersions(handle, intObj(12)))
	if errObj != nil {
		t.Fatalf("ext_inode_versions(12): %s", errObj.Inspect())
	}
	if n := mustHashIntValue(t, payload.(*object.Hash), "entry_count"); n != 1 {
		t.Fatalf("the fixture's journal holds %d versions of inode 12, want 1: %s", n, payload.Inspect())
	}

	for _, inode := range []int64{1<<32 + 12, 17} {
		if payload, errObj := unwrapPair(t, ExtInodeVersions(handle, intObj(inode))); errObj == nil {
			t.Errorf("ext_inode_versions(%d) answered: %s", inode, payload.Inspect())
		}
		out := filepath.Join(dir, fmt.Sprintf("inode-%d.bin", inode))
		if payload, errObj := unwrapPair(t, ExtRecoverJournalledFile(handle, intObj(inode), intObj(0), stringObj(out))); errObj == nil {
			t.Errorf("ext_recover_journalled_file(%d) recovered: %s", inode, payload.Inspect())
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("ext_recover_journalled_file(%d) wrote %s", inode, out)
		}
	}
}
