package builtin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"mutant/object"
)

// HFS+ volumes laid out by hand, ported from libhfs v0.3.2's own test builders
// (xattr_test.go, catalog_test.go and deleted_test.go; MIT, aoiflux): a volume
// header, a catalog B-tree of one leaf and, where wanted, an attributes B-tree
// of one leaf and an allocation file. Field offsets are Apple's TN1150.
const (
	hfsFixBlockSize = 4096
	hfsFixNodeSize  = 1024
	hfsFixRootCNID  = 2
)

var hfsBE = binary.BigEndian

// hfsFixNode is a B-tree node: the 14-byte descriptor, the records, and the
// offsets to each record -- and to the free space after the last -- counted
// back from the node's end.
func hfsFixNode(nodeType int8, records [][]byte) []byte {
	node := make([]byte, hfsFixNodeSize)
	node[8] = byte(nodeType)
	hfsBE.PutUint16(node[10:12], uint16(len(records)))
	cur := 14
	starts := make([]int, 0, len(records)+1)
	for _, record := range records {
		copy(node[cur:], record)
		starts = append(starts, cur)
		cur += len(record)
	}
	starts = append(starts, cur)
	for i, start := range starts {
		hfsBE.PutUint16(node[hfsFixNodeSize-2*(i+1):], uint16(start))
	}
	return node
}

// hfsFixHeaderNode is a tree's header node for a two-node tree whose root is
// its only leaf, node 1.
func hfsFixHeaderNode() []byte {
	r := make([]byte, 106)
	hfsBE.PutUint16(r[0:2], 2)
	hfsBE.PutUint32(r[2:6], 1) // root node
	hfsBE.PutUint32(r[6:10], 3)
	hfsBE.PutUint32(r[10:14], 1) // first leaf
	hfsBE.PutUint32(r[14:18], 1) // last leaf
	hfsBE.PutUint16(r[18:20], hfsFixNodeSize)
	hfsBE.PutUint16(r[20:22], 520)
	hfsBE.PutUint32(r[22:26], 2) // total nodes
	r[37] = 0xC7
	hfsBE.PutUint32(r[38:42], 4)
	return hfsFixNode(1, [][]byte{r})
}

func hfsFixCatalogKey(parent uint32, name string) []byte {
	units := utf16.Encode([]rune(name))
	key := make([]byte, 8+2*len(units))
	hfsBE.PutUint16(key[0:2], uint16(6+2*len(units)))
	hfsBE.PutUint32(key[2:6], parent)
	hfsBE.PutUint16(key[6:8], uint16(len(units)))
	for i, u := range units {
		hfsBE.PutUint16(key[8+2*i:], u)
	}
	return key
}

func hfsFixFolder(cnid, valence uint32) []byte {
	r := make([]byte, 88)
	hfsBE.PutUint16(r[0:2], 1) // folder record
	hfsBE.PutUint32(r[4:8], valence)
	hfsBE.PutUint32(r[8:12], cnid)
	return r
}

// hfsFixFile is a file record whose data fork is size bytes in the one extent
// start..start+blocks.
func hfsFixFile(cnid uint32, size uint64, start, blocks uint32) []byte {
	r := make([]byte, 248)
	hfsBE.PutUint16(r[0:2], 2) // file record
	hfsBE.PutUint32(r[8:12], cnid)
	hfsBE.PutUint64(r[88:96], size)
	hfsBE.PutUint32(r[100:104], blocks)
	hfsBE.PutUint32(r[104:108], start)
	hfsBE.PutUint32(r[108:112], blocks)
	return r
}

func hfsFixAttrKey(cnid, startBlock uint32, name string) []byte {
	units := utf16.Encode([]rune(name))
	key := make([]byte, 14+2*len(units))
	hfsBE.PutUint16(key[0:2], uint16(12+2*len(units)))
	hfsBE.PutUint32(key[4:8], cnid)
	hfsBE.PutUint32(key[8:12], startBlock)
	hfsBE.PutUint16(key[12:14], uint16(len(units)))
	for i, u := range units {
		hfsBE.PutUint16(key[14+2*i:], u)
	}
	return key
}

// hfsFixInline is an inline attribute record declaring declared bytes and
// holding value.
func hfsFixInline(value []byte, declared uint32) []byte {
	r := make([]byte, 16+len(value))
	hfsBE.PutUint32(r[0:4], 0x10)
	hfsBE.PutUint32(r[12:16], declared)
	copy(r[16:], value)
	return r
}

func hfsFixForkRecord(size uint64, extents [][2]uint32) []byte {
	r := make([]byte, 8+80)
	hfsBE.PutUint32(r[0:4], 0x20)
	hfsBE.PutUint64(r[8:16], size)
	var blocks uint32
	for i, e := range extents {
		blocks += e[1]
		hfsBE.PutUint32(r[8+16+8*i:], e[0])
		hfsBE.PutUint32(r[8+20+8*i:], e[1])
	}
	hfsBE.PutUint32(r[8+12:8+16], blocks)
	return r
}

func hfsFixExtensionRecord(extents [][2]uint32) []byte {
	r := make([]byte, 8+64)
	hfsBE.PutUint32(r[0:4], 0x30)
	for i, e := range extents {
		hfsBE.PutUint32(r[8+8*i:], e[0])
		hfsBE.PutUint32(r[12+8*i:], e[1])
	}
	return r
}

// hfsFixVolume writes the volume header: HFS+, the block size, the block count
// and the forks of the special files that are present -- each one block.
func hfsFixVolume(img []byte, catalog, attributes, allocation uint32) {
	vh := img[1024 : 1024+512]
	hfsBE.PutUint16(vh[0:2], 0x482B) // "H+"
	hfsBE.PutUint16(vh[2:4], 4)
	hfsBE.PutUint32(vh[40:44], hfsFixBlockSize)
	hfsBE.PutUint32(vh[44:48], uint32(len(img)/hfsFixBlockSize))
	hfsBE.PutUint32(vh[48:52], 2)
	hfsBE.PutUint32(vh[64:68], 1000) // next catalog ID
	fork := func(at int, block uint32) {
		if block == 0 {
			return
		}
		hfsBE.PutUint64(vh[at:at+8], hfsFixBlockSize)
		hfsBE.PutUint32(vh[at+12:at+16], 1)
		hfsBE.PutUint32(vh[at+16:at+20], block)
		hfsBE.PutUint32(vh[at+20:at+24], 1)
	}
	fork(112, allocation)
	fork(272, catalog)
	fork(352, attributes)
}

func hfsFixPutTree(img []byte, block uint32, leaf []byte) {
	at := int(block) * hfsFixBlockSize
	copy(img[at:], hfsFixHeaderNode())
	copy(img[at+hfsFixNodeSize:], leaf)
}

// The fragmented attribute's nine extents, as libhfs's own fixture has them:
// never adjacent, so a reader that assumes they are reads other bytes.
var hfsFixForkExtents = [][2]uint32{{10, 1}, {12, 1}, {14, 1}, {16, 1}, {18, 1}, {20, 1}, {22, 1}, {24, 1}, {26, 1}}

const hfsFixForkSize = 9*hfsFixBlockSize - 1234

// buildHFSXattrVolume is a volume of three files: forked.bin (CNID 101), whose
// attribute user.big is fork-backed in hfsFixForkExtents, each extent filled
// with the byte 0xA0 + its index; and bad1.txt and bad2.txt (CNIDs 104, 105),
// each with an inline attribute declaring 64 bytes and holding 3 -- the same
// damage twice.
func buildHFSXattrVolume() []byte {
	img := make([]byte, 27*hfsFixBlockSize)
	hfsFixVolume(img, 2, 4, 0)
	hfsFixPutTree(img, 2, hfsFixNode(-1, [][]byte{
		append(hfsFixCatalogKey(hfsFixRootCNID, ""), hfsFixFolder(hfsFixRootCNID, 3)...),
		append(hfsFixCatalogKey(hfsFixRootCNID, "bad1.txt"), hfsFixFile(104, 0, 0, 0)...),
		append(hfsFixCatalogKey(hfsFixRootCNID, "bad2.txt"), hfsFixFile(105, 0, 0, 0)...),
		append(hfsFixCatalogKey(hfsFixRootCNID, "forked.bin"), hfsFixFile(101, 0, 0, 0)...),
	}))
	hfsFixPutTree(img, 4, hfsFixNode(-1, [][]byte{
		append(hfsFixAttrKey(101, 0, "user.big"), hfsFixForkRecord(hfsFixForkSize, hfsFixForkExtents[:8])...),
		append(hfsFixAttrKey(101, 8, "user.big"), hfsFixExtensionRecord(hfsFixForkExtents[8:])...),
		append(hfsFixAttrKey(104, 0, "user.bad"), hfsFixInline([]byte("abc"), 64)...),
		append(hfsFixAttrKey(105, 0, "user.bad"), hfsFixInline([]byte("abc"), 64)...),
	}))
	for i, e := range hfsFixForkExtents {
		for j := int(e[0]) * hfsFixBlockSize; j < int(e[0]+e[1])*hfsFixBlockSize; j++ {
			img[j] = byte(0xA0 + i)
		}
	}
	return img
}

// buildHFSDeletedRecordVolume is an eight-block volume with one live file
// and, in the free space of the catalog leaf, the record of a deleted one:
// CNID 500, "gone.txt", its data fork recordBlocks blocks from block 6 -- one
// fits, more run past the volume. The allocation file in block 5 marks blocks
// 0-2 and 5 in use, and block 6 when block6InUse; block 7 is free.
func buildHFSDeletedRecordVolume(block6InUse bool, recordBlocks uint32) []byte {
	img := make([]byte, 8*hfsFixBlockSize)
	bitmap := byte(0xE4) // blocks 0, 1, 2 and 5; the high bit is block 0
	if block6InUse {
		bitmap |= 0x02
	}
	img[5*hfsFixBlockSize] = bitmap
	hfsFixVolume(img, 2, 0, 5)
	leaf := hfsFixNode(-1, [][]byte{
		append(hfsFixCatalogKey(hfsFixRootCNID, ""), hfsFixFolder(hfsFixRootCNID, 1)...),
		append(hfsFixCatalogKey(hfsFixRootCNID, "kept.txt"), hfsFixFile(300, 0, 0, 0)...),
	})
	free := int(hfsBE.Uint16(leaf[hfsFixNodeSize-6:])) // the third offset: where free space begins
	copy(leaf[free:], append(hfsFixCatalogKey(hfsFixRootCNID, "gone.txt"), hfsFixFile(500, uint64(recordBlocks)*hfsFixBlockSize, 6, recordBlocks)...))
	hfsFixPutTree(img, 2, leaf)
	copy(img[6*hfsFixBlockSize:], "this content survived the deletion")
	return img
}

func openHFSImage(t *testing.T, image []byte) object.Object {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hfs.img")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	payload, errObj := unwrapPair(t, HFSOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("hfs_open: %s", errObj.Inspect())
	}
	handle := mustHashValue(t, payload.(*object.Hash), "handle")
	t.Cleanup(func() { HFSClose(handle) })
	return handle
}
