package builtin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A VHD small enough to build in a test, so that the sparse half of this
// family is exercised against real bytes rather than only against a fake.
//
// Nothing here is a general VHD writer. It emits the two layouts the extent
// code has to get right -- a fixed image, where every range is mapped, and a
// dynamic one, where the block allocation table decides which ranges exist at
// all -- and it emits them by hand from the format's own field order, so that
// a test asserting a file offset is asserting against a number this file put
// there rather than against whatever the reader happened to compute.
//
// The images are written into the test's own temporary directory and never
// into the repository. There is no VHD in the tree and there is no generator
// installed on the machines this is developed on, which is why this exists.

const (
	vhdSectorSize   = 512
	vhdFooterSize   = 512
	vhdDynHeaderLen = 1024

	vhdDiskTypeFixed        = 2
	vhdDiskTypeDynamic      = 3
	vhdDiskTypeDifferencing = 4
)

// vhdEpoch is the VHD timestamp origin: seconds since 2000-01-01 UTC, not the
// Unix epoch. A footer stamped from time.Now().Unix() parses as a date in 2070.
var vhdEpoch = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// vhdChecksum is the VHD structure checksum: the one's complement of the sum of
// every byte with the checksum field itself zeroed. It is not a CRC; CRC-32C
// belongs to VHDX.
func vhdChecksum(buf []byte, at int) uint32 {
	var sum uint32
	for i, b := range buf {
		if i >= at && i < at+4 {
			continue
		}
		sum += uint32(b)
	}
	return ^sum
}

// vhdGeometry is the CHS derivation from the VHD specification. The encoding
// tops out near 127 GB, and every fixture here is far below that.
func vhdGeometry(totalSectors uint64) (cylinders uint16, heads, sectorsPerTrack uint8) {
	var spt, hd, cth uint64
	switch {
	case totalSectors >= 65535*16*63:
		spt, hd = 255, 16
		cth = totalSectors / spt
	default:
		spt = 17
		cth = totalSectors / spt
		hd = (cth + 1023) / 1024
		if hd < 4 {
			hd = 4
		}
		if cth >= hd*1024 || hd > 16 {
			spt, hd = 31, 16
			cth = totalSectors / spt
		}
		if cth >= hd*1024 {
			spt, hd = 63, 16
			cth = totalSectors / spt
		}
	}
	return uint16(cth / hd), uint8(hd), uint8(spt)
}

// vhdFooter builds the 512-byte footer both layouts carry.
func vhdFooter(virtualSize uint64, diskType uint32, dataOffset uint64, id [16]byte) []byte {
	buf := make([]byte, vhdFooterSize)
	copy(buf[0:8], "conectix")
	binary.BigEndian.PutUint32(buf[8:12], 0x00000002)  // features: reserved bit
	binary.BigEndian.PutUint32(buf[12:16], 0x00010000) // file format version 1.0
	binary.BigEndian.PutUint64(buf[16:24], dataOffset)
	binary.BigEndian.PutUint32(buf[24:28], uint32(time.Now().UTC().Sub(vhdEpoch)/time.Second))
	copy(buf[28:32], "mtnt")
	binary.BigEndian.PutUint32(buf[32:36], 0x00010000)
	copy(buf[36:40], "Wi2k")
	binary.BigEndian.PutUint64(buf[40:48], virtualSize) // original size
	binary.BigEndian.PutUint64(buf[48:56], virtualSize) // current size

	cylinders, heads, spt := vhdGeometry(virtualSize / vhdSectorSize)
	binary.BigEndian.PutUint16(buf[56:58], cylinders)
	buf[58] = heads
	buf[59] = spt
	binary.BigEndian.PutUint32(buf[60:64], diskType)
	copy(buf[68:84], id[:])
	binary.BigEndian.PutUint32(buf[64:68], vhdChecksum(buf, 64))
	return buf
}

// vhdDynamicHeader builds the 1024-byte header a dynamic image carries after
// its mirrored footer.
func vhdDynamicHeader(tableOffset uint64, maxTableEntries, blockSize uint32) []byte {
	buf := make([]byte, vhdDynHeaderLen)
	copy(buf[0:8], "cxsparse")
	binary.BigEndian.PutUint64(buf[8:16], 0xFFFFFFFFFFFFFFFF) // data offset: none
	binary.BigEndian.PutUint64(buf[16:24], tableOffset)
	binary.BigEndian.PutUint32(buf[24:28], 0x00010000)
	binary.BigEndian.PutUint32(buf[28:32], maxTableEntries)
	binary.BigEndian.PutUint32(buf[32:36], blockSize)
	binary.BigEndian.PutUint32(buf[36:40], vhdChecksum(buf, 36))
	return buf
}

// writeFixedVHD writes an image whose every byte is stored: payload followed by
// the footer. Its extent map is one mapped run covering the device.
func writeFixedVHD(t *testing.T, path string, payload []byte, id [16]byte) {
	t.Helper()

	size := uint64(len(payload))
	if size%vhdSectorSize != 0 {
		t.Fatalf("fixed VHD payload must be a whole number of sectors, got %d", size)
	}

	out := append([]byte(nil), payload...)
	out = append(out, vhdFooter(size, vhdDiskTypeFixed, 0xFFFFFFFFFFFFFFFF, id)...)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// writeDynamicVHD writes a sparse image: only the blocks named in present are
// stored, and every other block of the device exists nowhere in the file.
//
// blocks is indexed by block number; a nil entry is a block that was never
// written and must come back as a zero extent rather than as stored zeroes.
func writeDynamicVHD(t *testing.T, path string, blockSize uint32, blocks [][]byte, id [16]byte) {
	t.Helper()

	entries := uint32(len(blocks))
	virtualSize := uint64(blockSize) * uint64(entries)

	// The bitmap that precedes each block's data is one bit per sector, rounded
	// up to a whole sector. Every sector of a stored block is present here.
	bitmapBytes := (blockSize / vhdSectorSize) / 8
	bitmapSectors := (bitmapBytes + vhdSectorSize - 1) / vhdSectorSize
	if bitmapSectors == 0 {
		bitmapSectors = 1
	}
	bitmapLen := bitmapSectors * vhdSectorSize

	tableOffset := uint64(vhdFooterSize + vhdDynHeaderLen)
	tableLen := uint32(entries) * 4
	tableLen = ((tableLen + vhdSectorSize - 1) / vhdSectorSize) * vhdSectorSize

	table := make([]byte, tableLen)
	for i := range table {
		table[i] = 0xFF // unallocated is all ones, not zero
	}

	body := []byte{}
	nextSector := uint32(tableOffset+uint64(tableLen)) / vhdSectorSize
	for i, block := range blocks {
		if block == nil {
			continue
		}
		if uint32(len(block)) != blockSize {
			t.Fatalf("block %d is %d bytes, want %d", i, len(block), blockSize)
		}
		binary.BigEndian.PutUint32(table[i*4:(i+1)*4], nextSector)

		bitmap := make([]byte, bitmapLen)
		for b := uint32(0); b < bitmapBytes; b++ {
			bitmap[b] = 0xFF
		}
		body = append(body, bitmap...)
		body = append(body, block...)
		nextSector += (bitmapLen + blockSize) / vhdSectorSize
	}

	footer := vhdFooter(virtualSize, vhdDiskTypeDynamic, uint64(vhdFooterSize), id)

	out := append([]byte(nil), footer...) // the mirror at offset 0
	out = append(out, vhdDynamicHeader(tableOffset, entries, blockSize)...)
	out = append(out, table...)
	out = append(out, body...)
	out = append(out, footer...) // and the conformant copy in the final sector

	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// vhdBlockDataOffset is where writeDynamicVHD put the data of the nth stored
// block, counting stored blocks rather than block numbers. It is the number a
// mapped extent's file_offset has to agree with.
func vhdBlockDataOffset(blockSize uint32, storedIndex, entries int) int64 {
	bitmapBytes := (blockSize / vhdSectorSize) / 8
	bitmapSectors := (bitmapBytes + vhdSectorSize - 1) / vhdSectorSize
	if bitmapSectors == 0 {
		bitmapSectors = 1
	}
	bitmapLen := int64(bitmapSectors * vhdSectorSize)

	tableLen := int64(entries) * 4
	tableLen = ((tableLen + vhdSectorSize - 1) / vhdSectorSize) * vhdSectorSize

	start := int64(vhdFooterSize+vhdDynHeaderLen) + tableLen
	return start + int64(storedIndex)*(bitmapLen+int64(blockSize)) + bitmapLen
}

// vhdFixtureDir makes a directory holding the images a test names, and returns
// it.
func vhdFixtureDir(t *testing.T) string {
	t.Helper()
	return filepath.Clean(t.TempDir())
}

// writeDifferencingVHD writes a child over parentPath: a disk that stores only
// the blocks it owns and reads the rest from its parent.
//
// owned is indexed by block number. A true entry is a block the child wrote and
// claims every sector of; a false entry is left unallocated, which is how VHD
// says "read this from the parent". There is no third state, and that absence
// is the reason a deletion cannot be recorded on a VHD chain at all.
func writeDifferencingVHD(t *testing.T, path, parentPath string, blockSize uint32, owned []bool, fill byte, id, parentID [16]byte) {
	t.Helper()

	entries := uint32(len(owned))
	virtualSize := uint64(blockSize) * uint64(entries)

	bitmapBytes := (blockSize / vhdSectorSize) / 8
	bitmapSectors := (bitmapBytes + vhdSectorSize - 1) / vhdSectorSize
	if bitmapSectors == 0 {
		bitmapSectors = 1
	}
	bitmapLen := bitmapSectors * vhdSectorSize

	tableOffset := uint64(vhdFooterSize + vhdDynHeaderLen)
	tableLen := uint32(entries) * 4
	tableLen = ((tableLen + vhdSectorSize - 1) / vhdSectorSize) * vhdSectorSize

	table := make([]byte, tableLen)
	for i := range table {
		table[i] = 0xFF
	}

	body := []byte{}
	nextSector := uint32(tableOffset+uint64(tableLen)) / vhdSectorSize
	for i, mine := range owned {
		if !mine {
			continue
		}
		binary.BigEndian.PutUint32(table[i*4:(i+1)*4], nextSector)

		bitmap := make([]byte, bitmapLen)
		for b := uint32(0); b < bitmapBytes; b++ {
			bitmap[b] = 0xFF
		}
		block := make([]byte, blockSize)
		for j := range block {
			block[j] = fill
		}
		body = append(body, bitmap...)
		body = append(body, block...)
		nextSector += (bitmapLen + blockSize) / vhdSectorSize
	}

	header := vhdDynamicHeader(tableOffset, entries, blockSize)
	copy(header[40:56], parentID[:])
	if info, err := os.Stat(parentPath); err == nil {
		binary.BigEndian.PutUint32(header[56:60], uint32(info.ModTime().UTC().Sub(vhdEpoch)/time.Second))
	}
	// The parent name is UTF-16 big-endian, which is the one field of this
	// header that is not a number and the one a resolver actually reads.
	name := filepath.Base(parentPath)
	for i, r := range []rune(name) {
		if 64+i*2+2 > 576 {
			break
		}
		binary.BigEndian.PutUint16(header[64+i*2:64+i*2+2], uint16(r))
	}
	binary.BigEndian.PutUint32(header[36:40], 0)
	binary.BigEndian.PutUint32(header[36:40], vhdChecksum(header, 36))

	footer := vhdFooter(virtualSize, vhdDiskTypeDifferencing, uint64(vhdFooterSize), id)

	out := append([]byte(nil), footer...)
	out = append(out, header...)
	out = append(out, table...)
	out = append(out, body...)
	out = append(out, footer...)

	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}
