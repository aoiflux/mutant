package builtin

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// buildExt2Image lays out the smallest ext2 volume libext opens and walks: 1 KiB
// blocks, one group, sixteen 128-byte inodes, and a root directory holding one
// regular file. The layout is ext2's on-disk format (e2fsprogs' ext2_fs.h): the
// superblock at byte 1024, the group descriptor table in the block after it,
// then the block bitmap, the inode bitmap, the inode table (blocks 5 and 6), the
// root directory's block (7) and the file's (8).
func buildExt2Image(name string, content []byte) []byte {
	const bs = 1024
	le16 := func(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
	le32 := func(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }

	img := make([]byte, 64*bs)
	sb := img[1024:2048]
	le32(sb, 0x00, 16)   // inodes
	le32(sb, 0x04, 64)   // blocks
	le32(sb, 0x0C, 55)   // free blocks
	le32(sb, 0x10, 4)    // free inodes
	le32(sb, 0x14, 1)    // first data block, for 1 KiB blocks
	le32(sb, 0x20, 8192) // blocks per group
	le32(sb, 0x24, 8192) // fragments per group
	le32(sb, 0x28, 16)   // inodes per group
	le16(sb, 0x38, 0xEF53)
	le16(sb, 0x3A, 1)    // cleanly unmounted
	le16(sb, 0x3C, 1)    // continue on errors
	le32(sb, 0x4C, 1)    // dynamic revision
	le32(sb, 0x54, 11)   // first non-reserved inode
	le16(sb, 0x58, 128)  // inode size
	le32(sb, 0x60, 0x02) // incompat: directory entries carry a file type

	gd := img[2*bs:]
	le32(gd, 0, 3)   // block bitmap
	le32(gd, 4, 4)   // inode bitmap
	le32(gd, 8, 5)   // inode table
	le16(gd, 12, 55) // free blocks
	le16(gd, 14, 4)  // free inodes
	le16(gd, 16, 1)  // directories

	img[3*bs] = 0xFF                    // blocks 1-8 in use; bit 0 is block 1
	img[4*bs], img[4*bs+1] = 0xFF, 0x0F // inodes 1-12 in use

	inode := func(n int) []byte { off := 5*bs + (n-1)*128; return img[off : off+128] }
	root := inode(2)
	le16(root, 0, 0x41ED) // directory, 0755
	le32(root, 4, bs)
	le16(root, 26, 3) // links
	le32(root, 28, 2) // 512-byte sectors
	le32(root, 40, 7) // i_block[0]
	file := inode(12)
	le16(file, 0, 0x81A4) // regular file, 0644
	le32(file, 4, uint32(len(content)))
	le16(file, 26, 1)
	le32(file, 28, 2)
	le32(file, 40, 8)

	dir := img[7*bs : 8*bs]
	entry := func(off int, ino uint32, recLen uint16, fileType byte, n string) {
		le32(dir, off, ino)
		le16(dir, off+4, recLen)
		dir[off+6], dir[off+7] = byte(len(n)), fileType
		copy(dir[off+8:], n)
	}
	entry(0, 2, 12, 2, ".")
	entry(12, 2, 12, 2, "..")
	entry(24, 12, bs-24, 1, name)
	copy(img[8*bs:], content)
	return img
}

// TestTheExt2FixtureIsAVolume holds the fixture to libext on its own, at offset
// zero, so the test below measures the offset and not the fixture.
func TestTheExt2FixtureIsAVolume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ext2.img")
	if err := os.WriteFile(path, buildExt2Image("hello.txt", []byte("hi\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	session, err := realEXTBackend{}.Open(path, fsRegion{})
	if err != nil {
		t.Fatalf("libext refused the fixture: %v", err)
	}
	defer session.Close()
	if got, err := session.ReadFile("/hello.txt"); err != nil || string(got) != "hi\n" {
		t.Fatalf("reading the fixture's file: %q, %v", got, err)
	}
}

// TestARealExtVolumeOpensAtItsOffsetInsideALargerImage is M26-FS1-001's
// regression test, the ext counterpart of FAT's: a real ext2 volume a megabyte
// into a larger file, opened at that offset, bounded and unbounded, listed and
// read. libext reads relative to the reader it is given, so handed the image
// from byte zero it looked for the superblock in the filler and refused a
// healthy volume as a corrupt one.
func TestARealExtVolumeOpensAtItsOffsetInsideALargerImage(t *testing.T) {
	content := []byte("evidence that sits a megabyte into the disk\n")
	image := buildExt2Image("hello.txt", content)
	const offset = 1048576
	path := embedVolume(t, image, offset, 4096)

	for _, region := range []fsRegion{{Offset: offset, Length: int64(len(image))}, {Offset: offset}} {
		session, err := realEXTBackend{}.Open(path, region)
		if err != nil {
			t.Fatalf("opening an ext volume at byte %d (length %d): %v", offset, region.Length, err)
		}
		entries, err := session.ListFiles("/")
		if err != nil {
			t.Fatalf("listing the embedded volume's root: %v", err)
		}
		var found bool
		for _, e := range entries {
			found = found || e.Name == "hello.txt"
		}
		if !found {
			t.Errorf("the embedded volume's root does not hold hello.txt: %+v", entries)
		}
		if got, err := session.ReadFile("/hello.txt"); err != nil || !bytes.Equal(got, content) {
			t.Errorf("reading hello.txt at length %d: %q, %v", region.Length, got, err)
		}
		_ = session.Close()
	}

	// And without the offset the same file is not a volume at all.
	if session, err := (realEXTBackend{}).Open(path, fsRegion{}); err == nil {
		_ = session.Close()
		t.Fatal("libext found an ext volume in a megabyte of filler")
	}
}
