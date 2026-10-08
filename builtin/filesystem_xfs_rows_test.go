package builtin

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

// A one-allocation-group XFS volume laid out by hand, ported from libxfs
// v0.4.1's own test builder (directory_fixture_test.go; MIT, aoiflux): 256
// blocks of 4 KiB, a superblock, an AGI whose 64 unlinked buckets hold
// NULLAGINO, an inode B-tree of one record marking inodes 0-63 allocated, and
// 256-byte inodes from block 2. Offsets are xfs_format.h's.
const (
	xfsFixBlockSize = 4096
	xfsFixInodeSize = 256
	xfsFixAGBlocks  = 256
	xfsFixRootInode = 32
	xfsFixAGI       = 2 * 512
	xfsFixNullInode = uint32(0xffffffff)
)

type xfsFixture struct {
	data    []byte
	version uint8 // 4 or 5
}

func newXFSFixture(version uint8) *xfsFixture {
	f := &xfsFixture{data: make([]byte, xfsFixAGBlocks*xfsFixBlockSize), version: version}
	sb := f.data
	copy(sb[0:4], "XFSB")
	binary.BigEndian.PutUint32(sb[4:8], xfsFixBlockSize)
	binary.BigEndian.PutUint64(sb[8:16], xfsFixAGBlocks) // sb_dblocks
	binary.BigEndian.PutUint64(sb[48:56], 32)
	binary.BigEndian.PutUint64(sb[56:64], xfsFixRootInode)
	binary.BigEndian.PutUint32(sb[84:88], xfsFixAGBlocks)
	binary.BigEndian.PutUint32(sb[88:92], 1) // one allocation group
	binary.BigEndian.PutUint16(sb[100:102], 0x0010|uint16(version))
	binary.BigEndian.PutUint16(sb[102:104], 512)
	binary.BigEndian.PutUint16(sb[104:106], xfsFixInodeSize)
	binary.BigEndian.PutUint16(sb[106:108], xfsFixBlockSize/xfsFixInodeSize)
	copy(sb[108:120], "FIXTURE")
	sb[123] = 4 // log2 inodes per block
	sb[124] = 8 // log2 blocks per AG
	binary.BigEndian.PutUint64(sb[128:136], 64)

	agi := sb[xfsFixAGI:]
	copy(agi[0:4], "XAGI")
	binary.BigEndian.PutUint32(agi[4:8], 1)
	binary.BigEndian.PutUint32(agi[12:16], xfsFixAGBlocks)
	binary.BigEndian.PutUint32(agi[16:20], 64)
	binary.BigEndian.PutUint32(agi[20:24], 5) // inode B-tree root
	binary.BigEndian.PutUint32(agi[24:28], 1)
	for bucket := 0; bucket < 64; bucket++ {
		binary.BigEndian.PutUint32(agi[40+4*bucket:], xfsFixNullInode)
	}

	btree := sb[5*xfsFixBlockSize:]
	record := 56
	copy(btree[0:4], "IAB3")
	if version == 4 {
		copy(btree[0:4], "IABT")
		record = 16
	}
	binary.BigEndian.PutUint16(btree[6:8], 1) // one record: inodes 0-63, none free
	_ = record
	return f
}

// writeInode writes an inode's core and returns where its data fork starts.
func (f *xfsFixture) writeInode(number uint64, mode uint16, format uint8, size uint64, extents uint32) []byte {
	inode := f.data[number*xfsFixInodeSize : (number+1)*xfsFixInodeSize]
	copy(inode[0:2], "IN")
	binary.BigEndian.PutUint16(inode[2:4], mode)
	inode[4] = 3
	if f.version == 4 {
		inode[4] = 2
	}
	inode[5] = format
	binary.BigEndian.PutUint32(inode[16:20], 1) // nlink
	binary.BigEndian.PutUint64(inode[56:64], size)
	binary.BigEndian.PutUint32(inode[76:80], extents)
	binary.BigEndian.PutUint32(inode[96:100], xfsFixNullInode) // di_next_unlinked
	if f.version == 5 {
		binary.BigEndian.PutUint64(inode[152:160], number)
		return inode[176:]
	}
	return inode[100:]
}

// writeRoot makes the root a short-form directory naming entries.
func (f *xfsFixture) writeRoot(entries map[string]uint64, names ...string) {
	payload := []byte{byte(len(names)), 0, 0, 0, 0, xfsFixRootInode}
	for _, name := range names {
		payload = append(payload, byte(len(name)), 0, 0)
		payload = append(payload, name...)
		if f.version == 5 {
			payload = append(payload, 1) // ftype: regular file; a lookup does not read it
		}
		child := make([]byte, 4)
		binary.BigEndian.PutUint32(child, uint32(entries[name]))
		payload = append(payload, child...)
	}
	copy(f.writeInode(xfsFixRootInode, 0o040755, 1, uint64(len(payload)), 0), payload)
}

// xfsFixExtent is a bmbt record: 54 bits of logical block, 52 of physical
// block and 21 of length, packed big-endian into 16 bytes.
func xfsFixExtent(logical, physical uint64, blocks uint32) []byte {
	out := make([]byte, 16)
	binary.BigEndian.PutUint64(out[0:8], (logical&0x3fffffffffffff)<<9|(physical>>43)&0x1ff)
	binary.BigEndian.PutUint64(out[8:16], (physical&0x7ffffffffff)<<21|uint64(blocks&0x1fffff))
	return out
}

// setTimes writes an inode's access, modification and change times in
// seconds (each followed by a zero nanosecond word); a v5 inode's creation
// time is left zero, which is what one never stamped holds.
func (f *xfsFixture) setTimes(number uint64, atime, mtime, ctime uint32) {
	inode := f.data[number*xfsFixInodeSize:]
	binary.BigEndian.PutUint32(inode[32:36], atime)
	binary.BigEndian.PutUint32(inode[40:44], mtime)
	binary.BigEndian.PutUint32(inode[48:52], ctime)
}

// unlink puts inode on its AGI bucket's chain, alone.
func (f *xfsFixture) unlink(agino uint32) {
	binary.BigEndian.PutUint32(f.data[xfsFixAGI+40+4*int(agino%64):], agino)
}

func openXFSImage(t *testing.T, image []byte) object.Object {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xfs.img")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	payload, errObj := unwrapPair(t, XFSOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("xfs_open: %s", errObj.Inspect())
	}
	handle := mustHashValue(t, payload.(*object.Hash), "handle")
	t.Cleanup(func() { XFSClose(handle) })
	return handle
}

// TestAnXFSReportBoundsItsVolume is M26-FS1-015's regression test. libxfs's
// report carries no volume range and xfs_report filled in none, so both
// fields read 0 on every volume -- one a megabyte into a disk image included.
func TestAnXFSReportBoundsItsVolume(t *testing.T) {
	f := newXFSFixture(5)
	f.writeRoot(nil)
	const offset = 1 << 20
	for _, start := range []int64{0, offset} {
		path := embedVolume(t, f.data, int(start), 4096)
		session, err := realXFSBackend{}.Open(path, fsRegion{Offset: start})
		if err != nil {
			t.Fatalf("opening the volume at %d: %v", start, err)
		}
		report, err := session.Report()
		_ = session.Close()
		if err != nil {
			t.Fatalf("xfs report at %d: %v", start, err)
		}
		if want := start + xfsFixAGBlocks*xfsFixBlockSize; report.StartOffset != start || report.EndOffset != want {
			t.Errorf("a volume at byte %d reports [%d, %d), want [%d, %d)",
				start, report.StartOffset, report.EndOffset, start, want)
		}
	}
}

// TestAnUnreadableXFSUnlinkedInodeIsNotComplete is M26-FS2-013's regression
// test: bucket 12 names inode 140, whose slot carries an inode's magic, so
// libxfs follows the chain through it, but which no inode B-tree record
// holds, so opening it fails. xfs_unlinked judged completeness before the loop
// that warns about an inode it cannot read, so it said complete beside the
// warning and unreadable 1.
func TestAnUnreadableXFSUnlinkedInodeIsNotComplete(t *testing.T) {
	f := newXFSFixture(5)
	f.writeRoot(nil)
	f.writeInode(140, 0, 2, 0, 0)
	f.unlink(140)
	payload, errObj := unwrapPair(t, XFSUnlinked(openXFSImage(t, f.data)))
	if errObj != nil {
		t.Fatalf("xfs_unlinked: %s", errObj.Inspect())
	}
	scan := payload.(*object.Hash)
	if mustHashIntValue(t, scan, "unreadable") == 0 {
		t.Fatalf("the fixture's inode 140 read: %s", scan.Inspect())
	}
	if mustHashBoolValue(t, scan, "complete") {
		t.Errorf("a scan that could not read an unlinked inode says complete: %s", scan.Inspect())
	}
}

// TestAZeroXFSTimeIsNoTime is M26-FS2-014's regression test: a v4 inode has no
// creation time and this one was never accessed. time.Unix(0, 0) is the epoch,
// not Go's zero time, so both read as 1970-01-01T00:00:00Z in xfs_unlinked,
// and the access time did in xfs_metadata.
func TestAZeroXFSTimeIsNoTime(t *testing.T) {
	f := newXFSFixture(4)
	f.writeRoot(map[string]uint64{"file": 35}, "file")
	f.writeInode(35, 0o100644, 2, 0, 0)
	f.setTimes(35, 0, 1700000000, 1700000000)
	f.unlink(35)
	handle := openXFSImage(t, f.data)

	payload, errObj := unwrapPair(t, XFSUnlinked(handle))
	if errObj != nil {
		t.Fatalf("xfs_unlinked: %s", errObj.Inspect())
	}
	entries := mustHashArrayValue(t, payload.(*object.Hash), "entries")
	if len(entries) != 1 {
		t.Fatalf("%d unlinked entries, want inode 35's: %s", len(entries), payload.Inspect())
	}
	entry := entries[0].(*object.Hash)
	for field, want := range map[string]string{"created_at": "", "accessed_at": "", "modified_at": "2023-11-14T22:13:20Z"} {
		if got := mustHashStringValue(t, entry, field); got != want {
			t.Errorf("xfs_unlinked %s = %q, want %q", field, got, want)
		}
	}

	payload, errObj = unwrapPair(t, XFSMetadata(handle, stringObj("/file")))
	if errObj != nil {
		t.Fatalf("xfs_metadata: %s", errObj.Inspect())
	}
	if got := mustHashStringValue(t, payload.(*object.Hash), "accessed_at"); got != "" {
		t.Errorf("xfs_metadata accessed_at = %q for a time never set", got)
	}
}

// TestAnXFSDirectoryIndexIsNotSlack is M26-FS2-020's regression test. A
// leaf-format directory keeps its leaf block 32 GiB into its address space,
// past the data section di_size measures. xfs_slack counted it: allocated_bytes
// came out at 32 GiB and the live leaf block was reported as file slack.
func TestAnXFSDirectoryIndexIsNotSlack(t *testing.T) {
	f := newXFSFixture(5)
	f.writeRoot(map[string]uint64{"dir": 34}, "dir")
	fork := f.writeInode(34, 0o040755, 2, xfsFixBlockSize, 2)
	copy(fork, xfsFixExtent(0, 8, 1))                            // the data block
	copy(fork[16:], xfsFixExtent((1<<35)/xfsFixBlockSize, 9, 1)) // the leaf block

	payload, errObj := unwrapPair(t, XFSSlack(openXFSImage(t, f.data), stringObj("/dir")))
	if errObj != nil {
		t.Fatalf("xfs_slack: %s", errObj.Inspect())
	}
	scan := payload.(*object.Hash)
	if got := mustHashIntValue(t, scan, "allocated_bytes"); got != xfsFixBlockSize {
		t.Errorf("allocated_bytes = %d, want the data section's %d", got, xfsFixBlockSize)
	}
	if ranges := mustHashArrayValue(t, scan, "ranges"); len(ranges) != 0 {
		t.Errorf("a directory's index blocks were reported as slack: %s", scan.Inspect())
	}
}

// sealCRCs stamps the superblock's and the named v3 inodes' CRC32c as XFS
// stores them: crc32c over the sector or the inode with the field zeroed,
// little-endian.
func (f *xfsFixture) sealCRCs(inodes ...uint64) {
	table := crc32.MakeTable(crc32.Castagnoli)
	seal := func(b []byte, at int) {
		clear(b[at : at+4])
		binary.LittleEndian.PutUint32(b[at:], crc32.Checksum(b, table))
	}
	seal(f.data[:512], 224)
	for _, n := range inodes {
		seal(f.data[n*xfsFixInodeSize:(n+1)*xfsFixInodeSize], 100)
	}
}

// xfsAnomalyCodes maps each anomaly code in a report to where it was seen.
func xfsAnomalyCodes(t *testing.T, report *object.Hash) map[string][]string {
	t.Helper()
	codes := map[string][]string{}
	for _, a := range mustHashArrayValue(t, report, "anomalies") {
		anomaly := a.(*object.Hash)
		code := mustHashStringValue(t, anomaly, "code")
		codes[code] = append(codes[code], mustHashStringValue(t, anomaly, "location"))
	}
	return codes
}

// TestAHealthyXFSv5VolumeIsNotACRCMismatch is the regression test for
// libxfs's byte-order error: it reads the stored superblock and inode CRCs
// big-endian where XFS stores them little-endian, so every v5 superblock and
// every v3 inode "failed". A freshly made, xfs_repair-clean volume was not
// verified, with a critical CRC finding, and its report carried a mismatch
// anomaly per inode. An edited superblock and inode must still be caught.
func TestAHealthyXFSv5VolumeIsNotACRCMismatch(t *testing.T) {
	f := newXFSFixture(5)
	f.writeRoot(map[string]uint64{"file": 35}, "file")
	f.writeInode(35, 0o100644, 2, 0, 0)
	f.sealCRCs(xfsFixRootInode, 35)

	handle := openXFSImage(t, f.data)
	payload, errObj := unwrapPair(t, XFSVerify(handle))
	if errObj != nil {
		t.Fatalf("xfs_verify: %s", errObj.Inspect())
	}
	if verify := payload.(*object.Hash); !mustHashBoolValue(t, verify, "verified") {
		t.Errorf("a volume whose CRCs all hold is not verified: %s", verify.Inspect())
	}
	payload, errObj = unwrapPair(t, XFSReport(handle))
	if errObj != nil {
		t.Fatalf("xfs_report: %s", errObj.Inspect())
	}
	report := payload.(*object.Hash)
	if codes := xfsAnomalyCodes(t, report); len(codes["VERIFY_SUPERBLOCK_CRC_MISMATCH"])+len(codes["VERIFY_INODE_CRC_MISMATCH"]) > 0 {
		t.Errorf("a volume whose CRCs all hold reports CRC mismatches: %v", codes)
	}

	f.data[108] ^= 0x01                   // the label
	f.data[35*xfsFixInodeSize+40] ^= 0x01 // inode 35's modification time
	edited := openXFSImage(t, f.data)
	payload, errObj = unwrapPair(t, XFSVerify(edited))
	if errObj != nil {
		t.Fatalf("xfs_verify, edited: %s", errObj.Inspect())
	}
	if verify := payload.(*object.Hash); mustHashBoolValue(t, verify, "verified") {
		t.Errorf("a volume with an edited superblock verified: %s", verify.Inspect())
	}
	payload, errObj = unwrapPair(t, XFSReport(edited))
	if errObj != nil {
		t.Fatalf("xfs_report, edited: %s", errObj.Inspect())
	}
	codes := xfsAnomalyCodes(t, payload.(*object.Hash))
	if len(codes["VERIFY_SUPERBLOCK_CRC_MISMATCH"]) != 1 {
		t.Errorf("the edited superblock's mismatch is not reported: %v", codes)
	}
	if got := codes["VERIFY_INODE_CRC_MISMATCH"]; len(got) != 1 || got[0] != "inode 35" {
		t.Errorf("inode mismatches %v, want inode 35's alone", got)
	}
}
