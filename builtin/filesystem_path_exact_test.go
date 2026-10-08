package builtin

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"mutant/object"
)

// --- an exFAT volume ----------------------------------------------------------

// The exFAT volume these tests build: 512-byte sectors, 4 KiB clusters, the
// FAT at sector 24, the data region at sector 64 and the root directory in
// cluster 2. Entry sets carry valid checksums, so libxfat reads them strictly.
const (
	xfatVolSector       = 512
	xfatVolSPC          = 8
	xfatVolCluster      = xfatVolSector * xfatVolSPC
	xfatVolSectors      = 2048
	xfatVolFATOffset    = 24
	xfatVolFATSectors   = 8
	xfatVolDataOffset   = 64
	xfatVolClusterCount = (xfatVolSectors - xfatVolDataOffset) / xfatVolSPC
)

func xfatVolSetChecksum(set []byte) uint16 {
	var sum uint16
	for i, b := range set {
		if i == 2 || i == 3 {
			continue
		}
		sum = ((sum >> 1) | (sum << 15)) + uint16(b)
	}
	return sum
}

// xfatVolEntrySet is a file entry set: the primary, a stream extension
// declaring the file contiguous at cluster, and one name entry.
func xfatVolEntrySet(name string, deleted bool, cluster uint32, size uint64) []byte {
	units := utf16.Encode([]rune(name))
	set := make([]byte, 3*32)
	primary, stream, fname := set[0:32], set[32:64], set[64:96]
	primary[0], stream[0], fname[0] = 0x85, 0xC0, 0xC1
	if deleted {
		primary[0], stream[0], fname[0] = 0x05, 0x40, 0x41
	}
	primary[1] = 2
	binary.LittleEndian.PutUint16(primary[4:6], 0x20)
	binary.LittleEndian.PutUint32(primary[8:12], 0x50000000)
	binary.LittleEndian.PutUint32(primary[12:16], 0x50000000)
	binary.LittleEndian.PutUint32(primary[16:20], 0x50000000)
	stream[1] = 0x03
	stream[3] = byte(len(units))
	binary.LittleEndian.PutUint64(stream[8:16], size)
	binary.LittleEndian.PutUint32(stream[20:24], cluster)
	binary.LittleEndian.PutUint64(stream[24:32], size)
	for i, u := range units {
		binary.LittleEndian.PutUint16(fname[2+2*i:4+2*i], u)
	}
	binary.LittleEndian.PutUint16(primary[2:4], xfatVolSetChecksum(set))
	return set
}

func xfatVolClusterOffset(cluster uint32) int {
	return xfatVolDataOffset*xfatVolSector + int(cluster-2)*xfatVolCluster
}

func buildExFATVolume(sets [][]byte, contents map[uint32][]byte) []byte {
	img := make([]byte, xfatVolSectors*xfatVolSector)
	copy(img[0:3], []byte{0xEB, 0x76, 0x90})
	copy(img[3:11], "EXFAT   ")
	binary.LittleEndian.PutUint64(img[0x48:], xfatVolSectors)
	binary.LittleEndian.PutUint32(img[0x50:], xfatVolFATOffset)
	binary.LittleEndian.PutUint32(img[0x54:], xfatVolFATSectors)
	binary.LittleEndian.PutUint32(img[0x58:], xfatVolDataOffset)
	binary.LittleEndian.PutUint32(img[0x5C:], xfatVolClusterCount)
	binary.LittleEndian.PutUint32(img[0x60:], 2)
	binary.LittleEndian.PutUint32(img[0x64:], 0xCAFEBABE)
	binary.LittleEndian.PutUint16(img[0x68:], 0x0100)
	img[0x6C] = 9 // 512-byte sectors
	img[0x6D] = 3 // 8 sectors a cluster
	img[0x6E] = 1
	img[0x1FE], img[0x1FF] = 0x55, 0xAA
	fat := img[xfatVolFATOffset*xfatVolSector:]
	binary.LittleEndian.PutUint32(fat[0:], 0xFFFFFFF8)
	binary.LittleEndian.PutUint32(fat[4:], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(fat[8:], 0xFFFFFFFF)
	root := img[xfatVolClusterOffset(2):]
	at := 0
	for _, s := range sets {
		copy(root[at:], s)
		at += len(s)
	}
	for cluster, data := range contents {
		copy(img[xfatVolClusterOffset(cluster):], data)
	}
	return img
}

func openVolumeWith(t *testing.T, image []byte, open, closer func(...object.Object) object.Object) object.Object {
	t.Helper()
	path := filepath.Join(t.TempDir(), "volume.img")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	payload, errObj := unwrapPair(t, open(stringObj(path)))
	if errObj != nil {
		t.Fatalf("open: %s", errObj.Inspect())
	}
	handle := mustHashValue(t, payload.(*object.Hash), "handle")
	t.Cleanup(func() { closer(handle) })
	return handle
}

// TestALiveExFATFileIsNotShadowedByADeletedOne is M26-FS1-007's regression
// test. A deleted a.txt entry set sits ahead of a live a.txt -- a file deleted
// and written again, which is how many editors save. The listing shows both;
// the path took the first name match, so reading the live, listed file was
// refused as deleted and its metadata was the deleted entry's.
func TestALiveExFATFileIsNotShadowedByADeletedOne(t *testing.T) {
	live := []byte("LIVE FILE CONTENT")
	old := []byte("DELETED EARLIER FILE")
	handle := openVolumeWith(t, buildExFATVolume(
		[][]byte{xfatVolEntrySet("a.txt", true, 4, uint64(len(old))), xfatVolEntrySet("a.txt", false, 3, uint64(len(live)))},
		map[uint32][]byte{3: live, 4: old}), XFATOpen, XFATClose)

	content, errObj := unwrapPair(t, XFATReadFileBytes(handle, stringObj("/a.txt")))
	if errObj != nil {
		t.Errorf("reading the live, listed /a.txt: %s", errObj.Inspect())
	} else if got := string(content.(*object.Bytes).Value); got != string(live) {
		t.Errorf("/a.txt read %q, want the live file's %q", got, live)
	}

	if hashed, errObj := unwrapPair(t, XFATHashFile(handle, stringObj("/a.txt"), stringObj("sha256"))); errObj != nil {
		t.Errorf("hashing /a.txt: %s", errObj.Inspect())
	} else if sum := sha256.Sum256(live); mustHashStringValue(t, hashed.(*object.Hash), "digest") != hex.EncodeToString(sum[:]) {
		t.Errorf("/a.txt hashed to something other than the live file")
	}

	meta, errObj := unwrapPair(t, XFATMetadata(handle, stringObj("/a.txt")))
	if errObj != nil {
		t.Fatalf("xfat_metadata(/a.txt): %s", errObj.Inspect())
	}
	m := meta.(*object.Hash)
	if mustHashBoolValue(t, m, "deleted") || mustHashIntValue(t, m, "size") != int64(len(live)) {
		t.Errorf("xfat_metadata(/a.txt) describes the deleted entry: %s", m.Inspect())
	}
}

// A name only a deleted entry has still resolves to it -- the listing gives
// it a path, and its metadata says deleted -- but two deleted entries under one
// name are two files the path cannot tell apart, and are refused.
func TestADeletedExFATNameResolvesOnlyWhenItIsUnambiguous(t *testing.T) {
	handle := openVolumeWith(t, buildExFATVolume([][]byte{
		xfatVolEntrySet("only.txt", true, 3, 5),
		xfatVolEntrySet("twice.txt", true, 4, 5),
		xfatVolEntrySet("twice.txt", true, 5, 6),
	}, map[uint32][]byte{3: []byte("ONLY!"), 4: []byte("FIRST"), 5: []byte("SECOND")}), XFATOpen, XFATClose)

	meta, errObj := unwrapPair(t, XFATMetadata(handle, stringObj("/only.txt")))
	if errObj != nil {
		t.Fatalf("xfat_metadata of the one deleted only.txt: %s", errObj.Inspect())
	}
	if !mustHashBoolValue(t, meta.(*object.Hash), "deleted") {
		t.Errorf("only.txt is deleted and its metadata says otherwise")
	}

	if got, errObj := unwrapPairNoFatal(XFATMetadata(handle, stringObj("/twice.txt"))); errObj == nil {
		t.Errorf("a path two deleted entries share resolved to one of them: %s", got.Inspect())
	} else if !strings.Contains(errObj.Message, "2 deleted entries") {
		t.Errorf("the refusal does not say why: %s", errObj.Message)
	}
}

// --- an ext2 volume holding names a path could mistake ------------------------

// buildExt2NameTree lays out an ext2 volume in the shape buildExt2Image uses
// (1 KiB blocks, one group, sixteen 128-byte inodes, the inode table in blocks
// 5 and 6), whose root holds a directory "a" containing "b", a file named
// "a\b", and two files "x" and "x " that differ by a trailing space.
func buildExt2NameTree() []byte {
	const bs = 1024
	le16 := func(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
	le32 := func(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }

	img := make([]byte, 64*bs)
	sb := img[1024:2048]
	le32(sb, 0x00, 16)   // inodes
	le32(sb, 0x04, 64)   // blocks
	le32(sb, 0x0C, 51)   // free blocks: 1-12 are used
	le32(sb, 0x10, 0)    // free inodes
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
	le32(gd, 0, 3) // block bitmap
	le32(gd, 4, 4) // inode bitmap
	le32(gd, 8, 5) // inode table
	le16(gd, 12, 51)
	le16(gd, 14, 0)
	le16(gd, 16, 2) // directories

	img[3*bs], img[3*bs+1] = 0xFF, 0x0F // blocks 1-12
	img[4*bs], img[4*bs+1] = 0xFF, 0xFF // inodes 1-16

	inode := func(n int) []byte { off := 5*bs + (n-1)*128; return img[off : off+128] }
	dirInode := func(n int, block uint32, links uint16) {
		in := inode(n)
		le16(in, 0, 0x41ED)
		le32(in, 4, bs)
		le16(in, 26, links)
		le32(in, 28, 2)
		le32(in, 40, block)
	}
	fileInode := func(n int, block uint32, content string) {
		in := inode(n)
		le16(in, 0, 0x81A4)
		le32(in, 4, uint32(len(content)))
		le16(in, 26, 1)
		le32(in, 28, 2)
		le32(in, 40, block)
		copy(img[int(block)*bs:], content)
	}
	dirInode(2, 7, 3)
	dirInode(12, 8, 2)
	fileInode(13, 9, "CONTENT-OF-BACKSLASH-NAME\n")
	fileInode(14, 10, "CONTENT-OF-A-SLASH-B\n")
	fileInode(15, 11, "PLAIN\n")
	fileInode(16, 12, "TRAILING-SPACE\n")

	type rec struct {
		ino      uint32
		fileType byte
		name     string
	}
	dirBlock := func(block int, recs []rec) {
		dir := img[block*bs : (block+1)*bs]
		off := 0
		for i, r := range recs {
			length := (8 + len(r.name) + 3) &^ 3
			if i == len(recs)-1 {
				length = bs - off
			}
			le32(dir, off, r.ino)
			le16(dir, off+4, uint16(length))
			dir[off+6], dir[off+7] = byte(len(r.name)), r.fileType
			copy(dir[off+8:], r.name)
			off += length
		}
	}
	dirBlock(7, []rec{{2, 2, "."}, {2, 2, ".."}, {12, 2, "a"}, {13, 1, `a\b`}, {15, 1, "x"}, {16, 1, "x "}})
	dirBlock(8, []rec{{12, 2, "."}, {2, 2, ".."}, {14, 1, "b"}})
	return img
}

// TestAnExtPathNamesExactlyTheListedFile is M26-FS1-008's regression test. A
// backslash is an ordinary byte of an ext name -- systemd writes one into every
// escaped unit name -- and a name may end in a space. The path normaliser
// rewrote "\" as "/" and trimmed the path, and so did libext's own: the listed
// "/a\b" read the different file "/a/b", and the listed "/x " read "/x".
func TestAnExtPathNamesExactlyTheListedFile(t *testing.T) {
	handle := openVolumeWith(t, buildExt2NameTree(), ExtOpen, ExtClose)

	listed, errObj := unwrapPair(t, ExtListFiles(handle, stringObj("/")))
	if errObj != nil {
		t.Fatalf("ext_list_files: %s", errObj.Inspect())
	}
	paths := map[string]bool{}
	for _, e := range listed.(*object.Array).Elements {
		paths[mustHashStringValue(t, e.(*object.Hash), "path")] = true
	}
	for _, root := range []string{"/a", `/a\b`, "/x", "/x "} {
		if !paths[root] {
			t.Errorf("the listing does not give %q: %v", root, paths)
		}
	}

	for path, want := range map[string]string{
		`/a\b`: "CONTENT-OF-BACKSLASH-NAME\n",
		"/a/b": "CONTENT-OF-A-SLASH-B\n",
		"/x":   "PLAIN\n",
		"/x ":  "TRAILING-SPACE\n",
	} {
		got, errObj := unwrapPair(t, ExtReadFileBytes(handle, stringObj(path)))
		if errObj != nil {
			t.Errorf("reading %q: %s", path, errObj.Inspect())
			continue
		}
		if string(got.(*object.Bytes).Value) != want {
			t.Errorf("%q read %q, want %q", path, got.(*object.Bytes).Value, want)
		}
	}

	meta, errObj := unwrapPair(t, ExtMetadata(handle, stringObj(`/a\b`)))
	if errObj != nil {
		t.Fatalf(`ext_metadata("/a\b"): %s`, errObj.Inspect())
	}
	if name := mustHashStringValue(t, meta.(*object.Hash), "name"); name != `a\b` {
		t.Errorf(`ext_metadata("/a\b") names %q`, name)
	}
}
