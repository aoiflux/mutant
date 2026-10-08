package builtin

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	libntfs "github.com/aoiflux/libntfs"

	"mutant/object"
)

// The NTFS volume these tests build: 32 clusters of 4096 bytes, the $MFT at
// cluster 4 with 1024-byte records, its length whatever record 0's own $DATA
// run declares. Record 5 is the root and record 6 a deleted file whose one
// cluster, 10, holds 4096 bytes of 'D'. Built from libntfs's own exported
// layout constants and byte helpers, so the volume is the format libntfs reads.
const (
	ntfsVolClusterSize = 4096
	ntfsVolClusters    = 32
	ntfsVolMFTCluster  = 4
	ntfsVolRecordSize  = 1024
)

func ntfsVolUTF16(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(u))
	for i, c := range u {
		out[2*i], out[2*i+1] = byte(c), byte(c>>8)
	}
	return out
}

func ntfsVolResident(attrType uint32, attrID uint16, value []byte) []byte {
	length := libntfs.AlignUp(libntfs.ResidentAttributeHeaderSize+len(value), 8)
	attr := make([]byte, length)
	libntfs.WriteUint32LE(attr, 0, attrType)
	libntfs.WriteUint32LE(attr, 4, uint32(length))
	libntfs.WriteUint16LE(attr, 10, libntfs.ResidentAttributeHeaderSize)
	libntfs.WriteUint16LE(attr, 14, attrID)
	libntfs.WriteUint32LE(attr, 16, uint32(len(value)))
	libntfs.WriteUint16LE(attr, 20, libntfs.ResidentAttributeHeaderSize)
	copy(attr[libntfs.ResidentAttributeHeaderSize:], value)
	return attr
}

func ntfsVolFileName(parent uint64, name string, size uint64) []byte {
	encoded := ntfsVolUTF16(name)
	buf := make([]byte, 66+len(encoded))
	libntfs.WriteUint64LE(buf, 0, parent)
	libntfs.WriteUint16LE(buf, 6, 1)
	libntfs.WriteUint64LE(buf, 40, size)
	libntfs.WriteUint64LE(buf, 48, size)
	libntfs.WriteUint64LE(buf, 56, 0x20)
	buf[64] = uint8(len([]rune(name)))
	buf[65] = libntfs.NamespaceWin32
	copy(buf[66:], encoded)
	return buf
}

func ntfsVolStandardInfo() []byte {
	buf := make([]byte, 72)
	stamp := libntfs.TimeToNTFSTime(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	for i := 0; i < 4; i++ {
		libntfs.WriteUint64LE(buf, i*8, stamp)
	}
	libntfs.WriteUint32LE(buf, 32, 0x20)
	return buf
}

// ntfsVolData is a non-resident $DATA of one run, its length in clusters
// encoded in four bytes so it can declare far more than the volume holds.
func ntfsVolData(start byte, lengthClusters uint32, realSize uint64) []byte {
	run := []byte{0x14, 0, 0, 0, 0, start, 0x00}
	libntfs.WriteUint32LE(run, 1, lengthClusters)
	const runOffset = libntfs.NonResidentAttributeHeaderSize
	length := libntfs.AlignUp(runOffset+len(run), 8)
	attr := make([]byte, length)
	libntfs.WriteUint32LE(attr, 0, libntfs.AttrTypeData)
	libntfs.WriteUint32LE(attr, 4, uint32(length))
	attr[8] = 1
	libntfs.WriteUint16LE(attr, 10, runOffset)
	libntfs.WriteUint16LE(attr, 14, 2)
	libntfs.WriteUint64LE(attr, 24, uint64(lengthClusters)-1)
	libntfs.WriteUint16LE(attr, 32, runOffset)
	libntfs.WriteUint64LE(attr, 40, uint64(lengthClusters)*ntfsVolClusterSize)
	libntfs.WriteUint64LE(attr, 48, realSize)
	libntfs.WriteUint64LE(attr, 56, realSize)
	copy(attr[runOffset:], run)
	return attr
}

func ntfsVolRecord(flags uint16, name string, parent, size uint64, extra ...[]byte) []byte {
	const usaOffset = libntfs.MFTEntryHeaderSize
	usaSize := uint16(ntfsVolRecordSize/libntfs.UpdateSequenceStride) + 1
	first := libntfs.AlignUp(usaOffset+int(usaSize)*2, 8)
	buf := make([]byte, ntfsVolRecordSize)
	attrs := append([][]byte{
		ntfsVolResident(libntfs.AttrTypeStandardInfo, 0, ntfsVolStandardInfo()),
		ntfsVolResident(libntfs.AttrTypeFileName, 1, ntfsVolFileName(parent, name, size)),
	}, extra...)
	off := first
	for _, a := range attrs {
		copy(buf[off:], a)
		off += len(a)
	}
	libntfs.WriteUint32LE(buf, off, 0xFFFFFFFF)
	libntfs.WriteUint32LE(buf, 0, libntfs.MFTMagicFILE)
	libntfs.WriteUint16LE(buf, 4, usaOffset)
	libntfs.WriteUint16LE(buf, 6, usaSize)
	libntfs.WriteUint16LE(buf, 16, 1)
	libntfs.WriteUint16LE(buf, 18, 1)
	libntfs.WriteUint16LE(buf, 20, uint16(first))
	libntfs.WriteUint16LE(buf, 22, flags)
	libntfs.WriteUint32LE(buf, 24, uint32(libntfs.AlignUp(off+4, 8)))
	libntfs.WriteUint32LE(buf, 28, ntfsVolRecordSize)
	libntfs.WriteUint16LE(buf, 40, 3)
	const usn = 0x0A0B
	libntfs.WriteUint16LE(buf, usaOffset, usn)
	for i := 0; i < int(usaSize)-1; i++ {
		end := (i+1)*libntfs.UpdateSequenceStride - 2
		libntfs.WriteUint16LE(buf, usaOffset+2+i*2, libntfs.ReadUint16LE(buf, end))
		libntfs.WriteUint16LE(buf, end, usn)
	}
	return buf
}

// buildNTFSVolume returns the volume with its $MFT declaring mftClusters
// clusters -- 4 records each -- from the cluster the boot sector names.
func buildNTFSVolume(mftClusters uint32) []byte {
	image := make([]byte, ntfsVolClusters*ntfsVolClusterSize)
	boot := image[:libntfs.BootSectorSize]
	boot[0], boot[1], boot[2] = 0xEB, 0x52, 0x90
	copy(boot[3:11], libntfs.BootSectorOEMNameNTFS)
	libntfs.WriteUint16LE(boot, 11, 512)
	boot[13] = 8
	libntfs.WriteUint64LE(boot, 40, ntfsVolClusters*8)
	libntfs.WriteUint64LE(boot, 48, ntfsVolMFTCluster)
	libntfs.WriteUint64LE(boot, 56, ntfsVolMFTCluster)
	boot[64] = 0xF6 // a record is 2^10 bytes
	boot[68] = 0xF4
	libntfs.WriteUint16LE(boot, 510, libntfs.BootSectorMagic)

	place := func(n int, record []byte) {
		copy(image[ntfsVolMFTCluster*ntfsVolClusterSize+n*ntfsVolRecordSize:], record)
	}
	place(0, ntfsVolRecord(libntfs.MFTFlagInUse, "$MFT", 5, 0,
		ntfsVolData(ntfsVolMFTCluster, mftClusters, uint64(mftClusters)*ntfsVolClusterSize)))
	place(5, ntfsVolRecord(libntfs.MFTFlagInUse|0x0002, ".", 5, 0))
	place(6, ntfsVolRecord(0, "gone.txt", 5, 4096, ntfsVolData(10, 1, 4096)))
	copy(image[10*ntfsVolClusterSize:11*ntfsVolClusterSize], bytes.Repeat([]byte{'D'}, ntfsVolClusterSize))
	return image
}

// openNTFSVolume writes image to a file and opens it with ntfs_open, the way a
// script would.
func openNTFSVolume(t *testing.T, image []byte) object.Object {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ntfs.img")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	payload, errObj := unwrapPair(t, NtfsOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("ntfs_open: %s", errObj.Inspect())
	}
	handle := mustHashValue(t, payload.(*object.Hash), "handle")
	t.Cleanup(func() { NtfsClose(handle) })
	return handle
}

func ntfsFindingsMention(t *testing.T, verified *object.Hash, text string) bool {
	t.Helper()
	for _, f := range mustHashArrayValue(t, verified, "findings") {
		if strings.Contains(f.(*object.Hash).Inspect(), text) {
			return true
		}
	}
	return false
}

// A whole, healthy volume: verified, and its report built. The guard the
// fixes below must not trip -- a walk bounded by the image is the whole walk
// when the image holds the whole MFT.
func TestAWholeNTFSVolumeStillVerifiesAndReports(t *testing.T) {
	handle := openNTFSVolume(t, buildNTFSVolume(2))

	payload, errObj := unwrapPair(t, NtfsVerify(handle))
	if errObj != nil {
		t.Fatalf("ntfs_verify: %s", errObj.Inspect())
	}
	if result := payload.(*object.Hash); !mustHashBoolValue(t, result, "verified") {
		t.Fatalf("a whole, healthy volume is not verified: %s", result.Inspect())
	}
	if _, errObj := unwrapPair(t, NtfsReport(handle)); errObj != nil {
		t.Fatalf("ntfs_report refused a whole volume: %s", errObj.Inspect())
	}
}

// TestAnMFTTheImageCutsShortIsNotVerified is M26-FS1-005's regression test.
// The $MFT declares 16 records and the image ends after the eighth. libntfs
// answers records 8 to 15 with an I/O error, and ntfs_verify's default branch
// -- documented as never-written records -- swallowed it: examined fell, no
// finding was raised, and the volume verified on the half that was left.
func TestAnMFTTheImageCutsShortIsNotVerified(t *testing.T) {
	image := buildNTFSVolume(4)
	cut := ntfsVolMFTCluster*ntfsVolClusterSize + 8*ntfsVolRecordSize
	handle := openNTFSVolume(t, image[:cut])

	payload, errObj := unwrapPair(t, NtfsVerify(handle))
	if errObj != nil {
		t.Fatalf("ntfs_verify: %s", errObj.Inspect())
	}
	result := payload.(*object.Hash)
	if mustHashBoolValue(t, result, "verified") {
		t.Errorf("an MFT the image holds half of verified: %s", result.Inspect())
	}
	if !ntfsFindingsMention(t, result, "outside the image") {
		t.Errorf("no finding names the records past the end of the image: %s", result.Inspect())
	}
}

// A FILE record whose fixups hold and whose attributes do not parse is not a
// never-written slot either, and is not skipped in silence.
func TestAnMFTRecordThatWillNotParseIsAFinding(t *testing.T) {
	image := buildNTFSVolume(2)
	record := ntfsVolRecord(libntfs.MFTFlagInUse, "broken.txt", 5, 10)
	first := int(libntfs.ReadUint16LE(record, 20))
	libntfs.WriteUint32LE(record, first+4, 0xFFF0) // an attribute longer than its record
	copy(image[ntfsVolMFTCluster*ntfsVolClusterSize+7*ntfsVolRecordSize:], record)
	handle := openNTFSVolume(t, image)

	payload, errObj := unwrapPair(t, NtfsVerify(handle))
	if errObj != nil {
		t.Fatalf("ntfs_verify: %s", errObj.Inspect())
	}
	result := payload.(*object.Hash)
	if mustHashBoolValue(t, result, "verified") {
		t.Errorf("a volume with a record that would not parse verified: %s", result.Inspect())
	}
	if !ntfsFindingsMention(t, result, "MFT record 7") {
		t.Errorf("no finding names record 7: %s", result.Inspect())
	}
}

// TestAnMFTDeclaredPastTheImageIsNamedNotWalked is M26-FS1-006's regression
// test for ntfs_verify: 128 KiB of image, an $MFT run declaring 65,536
// records. The walk looped over every declared number -- linear in a count the
// evidence chose, hours at a billion -- and reported nothing about it.
func TestAnMFTDeclaredPastTheImageIsNamedNotWalked(t *testing.T) {
	handle := openNTFSVolume(t, buildNTFSVolume(0x4000))

	payload, errObj := unwrapPair(t, NtfsVerify(handle))
	if errObj != nil {
		t.Fatalf("ntfs_verify: %s", errObj.Inspect())
	}
	result := payload.(*object.Hash)
	if mustHashBoolValue(t, result, "verified") {
		t.Errorf("an MFT declaring 65536 records in 128 KiB verified: %s", result.Inspect())
	}
	if !ntfsFindingsMention(t, result, "65536") {
		t.Errorf("no finding states the declared count: %s", result.Inspect())
	}
}

// And for the report, which libntfs builds by its own walk over the declared
// count: it said complete over records it never read. It is refused now.
func TestAnNTFSReportOverAnMFTTheImageDoesNotHoldIsRefused(t *testing.T) {
	handle := openNTFSVolume(t, buildNTFSVolume(0x4000))

	_, errObj := unwrapPairNoFatal(NtfsReport(handle))
	if errObj == nil {
		t.Fatalf("ntfs_report built a report over an MFT declaring 65536 records in 128 KiB")
	}
	if !strings.Contains(errObj.Message, "65536") {
		t.Errorf("the refusal does not state the declared count: %s", errObj.Message)
	}
}

// ntfsDeletedScan runs ntfs_deleted over handle and holds the result to having
// done the work.
//
// A scan that failed, or found nothing, allocates nothing -- and nothing is a
// gap of zero, so the differential below would pass on a scan that never ran.
// Both fixtures hold the same single deleted record, so finding it is what says
// the scan happened. Neither check depends on the fix.
func ntfsDeletedScan(t *testing.T, handle object.Object, what string) *object.Hash {
	t.Helper()
	payload, errObj := unwrapPair(t, NtfsDeleted(handle))
	if errObj != nil {
		t.Fatalf("ntfs_deleted over %s: %s", what, errObj.Inspect())
	}
	result := payload.(*object.Hash)
	if count := mustHashIntValue(t, result, "entry_count"); count != 1 {
		t.Fatalf("ntfs_deleted over %s reported %d deleted entries, not the one the fixture holds: %s",
			what, count, result.Inspect())
	}
	return result
}

// TestNtfsDeletedDoesNotAllocateByTheDeclaredCount is M26-FS2-003's
// regression test. ScanDeleted preallocated make([]mftRow, 0, count) from the
// declared count before reading anything; at 2^32 clusters that is a request
// for a terabyte and an uncatchable fatal error. Here the declaration is
// 65,536 records -- small enough to run on the unfixed code -- and what the
// scan allocates must have nothing to do with it.
//
// The figure is a difference and not an absolute, for the reason
// allocation_gap_test.go sets out at length: TotalAlloc is process-wide and
// cumulative, so an absolute bound measures whatever else the package is doing,
// and tests written that way passed alone while failing a full run. The two
// volumes here are both 128 KiB and differ only in the bytes of the $MFT's own
// data run -- 8 records declared against 65,536 -- so the difference between
// the two scans is what the declared count bought, with the scan's own cost
// cancelled out of it. Measured on the unfixed code the gap is 75,522,616
// bytes against an allowance of 4,194,304, eighteen times over; bounded by the
// image it is the 104 further records the walk genuinely reaches.
//
// Both handles are opened before anything is measured. openNTFSVolume writes an
// image to a file and registers a t.Cleanup, and that work must not land in a
// reading taken five times a side.
func TestNtfsDeletedDoesNotAllocateByTheDeclaredCount(t *testing.T) {
	small := openNTFSVolume(t, buildNTFSVolume(2))
	huge := openNTFSVolume(t, buildNTFSVolume(0x4000))

	ntfsDeletedScan(t, small, "the volume declaring 8 records")
	hugeResult := ntfsDeletedScan(t, huge, "the volume declaring 65536 records")

	// Both volumes are incomplete, and only one of them for the reason this row
	// is about: five of the eight slots the small volume declares were never
	// written and do not parse, which is a different thing from a record the
	// image does not hold at all. The reason is what tells the two apart, so it
	// is the reason and not the flag that is asserted here.
	if mustHashBoolValue(t, hugeResult, "complete") {
		t.Errorf("a scan that did not read the declared records says complete")
	}
	if reason := mustHashStringValue(t, hugeResult, "incomplete_reason"); !strings.Contains(reason, "outside the image") {
		t.Errorf("the scan's reason does not name the records outside the image: %q", reason)
	}

	requireNoAllocationGap(t, "ntfs_deleted over an $MFT declaring 65536 records in a 128 KiB image",
		func() { NtfsDeleted(small) },
		func() { NtfsDeleted(huge) })
}
