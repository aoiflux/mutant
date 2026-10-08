package builtin

import (
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

func hfsXattrsOf(t *testing.T, handle object.Object, path string) *object.Hash {
	t.Helper()
	payload, errObj := unwrapPair(t, HFSXattrs(handle, stringObj(path)))
	if errObj != nil {
		t.Fatalf("hfs_xattrs %s: %s", path, errObj.Inspect())
	}
	return payload.(*object.Hash)
}

func hfsAttribute(t *testing.T, scan *object.Hash, name string) *object.Hash {
	t.Helper()
	for _, a := range mustHashArrayValue(t, scan, "attributes") {
		if attribute := a.(*object.Hash); mustHashStringValue(t, attribute, "name") == name {
			return attribute
		}
	}
	t.Fatalf("no attribute %s: %s", name, scan.Inspect())
	return nil
}

func hfsDeletedRow(t *testing.T, image []byte, cnid int64) (object.Object, int64, *object.Hash) {
	t.Helper()
	handle := openHFSImage(t, image)
	payload, errObj := unwrapPair(t, HFSDeleted(handle))
	if errObj != nil {
		t.Fatalf("hfs_deleted: %s", errObj.Inspect())
	}
	for i, e := range mustHashArrayValue(t, payload.(*object.Hash), "entries") {
		if row := e.(*object.Hash); mustHashIntValue(t, row, "record_id") == cnid {
			return handle, int64(i), row
		}
	}
	t.Fatalf("hfs_deleted reports no row for CNID %d: %s", cnid, payload.Inspect())
	return nil, 0, nil
}

// The fixtures, held to libhfs before the tests below lean on them.
func TestTheHFSFixturesAreVolumes(t *testing.T) {
	handle := openHFSImage(t, buildHFSXattrVolume())
	big := hfsAttribute(t, hfsXattrsOf(t, handle, "/forked.bin"), "user.big")
	if got := mustHashIntValue(t, big, "size"); got != hfsFixForkSize {
		t.Errorf("user.big is %d bytes, want %d", got, hfsFixForkSize)
	}
	_, _, row := hfsDeletedRow(t, buildHFSDeletedRecordVolume(false, 1), 500)
	if mustHashStringValue(t, row, "name") != "gone.txt" {
		t.Errorf("the deleted record is not gone.txt: %s", row.Inspect())
	}
}

// TestAFragmentedHFSAttributeReportsEveryRange is M26-FS2-022's regression
// test. A fork-backed value's offset was its first extent's, and the warning
// for a value past the render cap said its bytes "stay readable from the
// image": read for its size from that offset, the value ran from its first
// extent into the unrelated block after it. Now every range is reported, and
// a single offset only when the ranges follow one another.
func TestAFragmentedHFSAttributeReportsEveryRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hfs.img")
	image := buildHFSXattrVolume()
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	payload, errObj := unwrapPair(t, HFSOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("hfs_open: %s", errObj.Inspect())
	}
	handle := mustHashValue(t, payload.(*object.Hash), "handle")
	t.Cleanup(func() { HFSClose(handle) })

	scan := hfsXattrsOf(t, handle, "/forked.bin")
	big := hfsAttribute(t, scan, "user.big")
	if got := mustHashIntValue(t, big, "offset"); got != -1 {
		t.Errorf("a value in nine separate ranges reports the single offset %d", got)
	}
	if !mustHashBoolValue(t, big, "located") {
		t.Errorf("a value with nine ranges on the image is not located")
	}
	if !hasCode(hashWarningCodes(t, scan), "value_fragmented") {
		t.Errorf("nothing says the value is fragmented: %v", hashWarningCodes(t, scan))
	}
	ranges := mustHashArrayValue(t, big, "ranges")
	if len(ranges) != len(hfsFixForkExtents) {
		t.Fatalf("%d ranges, want %d: %s", len(ranges), len(hfsFixForkExtents), big.Inspect())
	}
	var total int64
	for i, r := range ranges {
		rng := r.(*object.Hash)
		offset, length := mustHashIntValue(t, rng, "offset"), mustHashIntValue(t, rng, "length")
		if want := int64(hfsFixForkExtents[i][0]) * hfsFixBlockSize; offset != want {
			t.Errorf("range %d at %d, want %d", i, offset, want)
		}
		for _, at := range []int64{offset, offset + length - 1} {
			if got := image[at]; got != byte(0xA0+i) {
				t.Errorf("range %d holds 0x%02X at %d, want the value's 0x%02X", i, got, at, 0xA0+i)
			}
		}
		total += length
	}
	if total != hfsFixForkSize {
		t.Errorf("the ranges hold %d bytes, want the value's %d", total, hfsFixForkSize)
	}
}

// TestRepeatedHFSAttributeDamageIsReportedEachTime is M26-FS2-021's
// regression test. libhfs lists an anomaly once per operation and detail for
// the life of the volume, so slicing the list around a call found the damage
// on the first file only: the second file with the same damage, and the first
// asked about again, reported none and said complete -- and even the first
// call said complete.
func TestRepeatedHFSAttributeDamageIsReportedEachTime(t *testing.T) {
	handle := openHFSImage(t, buildHFSXattrVolume())
	for _, path := range []string{"/bad1.txt", "/bad2.txt", "/bad1.txt"} {
		scan := hfsXattrsOf(t, handle, path)
		codes := hashWarningCodes(t, scan)
		if !hasCode(codes, "xattr_inline") && !hasCode(codes, "anomalies_repeated") {
			t.Errorf("%s: the truncated attribute record raised no warning: %v", path, codes)
		}
		if mustHashBoolValue(t, scan, "complete") {
			t.Errorf("%s: a node whose attribute record is truncated says complete", path)
		}
	}
}

// TestAnHFSRecordPastTheVolumeIsNotAllocationChecked is M26-FS2-016's
// regression test: the record's five blocks run from block 6 of an
// eight-block volume, so after blocks 6 and 7, both free, the allocation file
// cannot answer for the last three. libhfs stops its check there and leaves
// Overwritten false, and the entry was reported allocation_checked regardless
// -- checked, and found free.
func TestAnHFSRecordPastTheVolumeIsNotAllocationChecked(t *testing.T) {
	_, _, row := hfsDeletedRow(t, buildHFSDeletedRecordVolume(false, 5), 500)
	if mustHashBoolValue(t, row, "allocation_checked") || mustHashBoolValue(t, row, "reallocated") {
		t.Errorf("a record whose blocks run past the volume: %s", row.Inspect())
	}
}

// A record over a free block: checked, and not reallocated.
func TestAnHFSRecordOverAFreeBlockIsCheckedAndFree(t *testing.T) {
	_, _, row := hfsDeletedRow(t, buildHFSDeletedRecordVolume(false, 1), 500)
	if !mustHashBoolValue(t, row, "allocation_checked") || mustHashBoolValue(t, row, "reallocated") {
		t.Errorf("a record over a free block: %s", row.Inspect())
	}
}

// A record over a block in use: reallocated, and its recovery names the block.
func TestAnHFSRecordOverABlockInUseNamesTheBlock(t *testing.T) {
	handle, index, row := hfsDeletedRow(t, buildHFSDeletedRecordVolume(true, 1), 500)
	if !mustHashBoolValue(t, row, "allocation_checked") || !mustHashBoolValue(t, row, "reallocated") {
		t.Errorf("a record over a block in use: %s", row.Inspect())
	}
	out := filepath.Join(t.TempDir(), "gone.bin")
	payload, errObj := unwrapPair(t, HFSRecoverFile(handle, intObj(index), stringObj(out)))
	if errObj != nil {
		t.Fatalf("hfs_recover_file: %s", errObj.Inspect())
	}
	if !recoveryCaveatsMention(t, payload.(*object.Hash), "block 6 of the run is in use") {
		t.Errorf("the recovery does not name the block in use: %s", payload.Inspect())
	}
}

// TestAnHFSVolumeWithNoAttributesTreeIsNotFailedForIt is M26-FS1-011's
// regression test, on an HFS+ volume made without an attributes file. Classic
// HFS has no attributes B-tree at all, and HFS+ has one only once an attribute
// was written; hfs_verify read its header regardless and failed the volume,
// critically, for a tree the volume never had.
func TestAnHFSVolumeWithNoAttributesTreeIsNotFailedForIt(t *testing.T) {
	image := buildHFSDeletedRecordVolume(false, 1)
	// Every HFS+ volume has an extents overflow tree, empty or not; this one's
	// is in block 3.
	vh := image[1024 : 1024+512]
	hfsBE.PutUint64(vh[192:200], hfsFixBlockSize)
	hfsBE.PutUint32(vh[204:208], 1)
	hfsBE.PutUint32(vh[208:212], 3)
	hfsBE.PutUint32(vh[212:216], 1)
	hfsFixPutTree(image, 3, hfsFixNode(-1, nil))
	handle := openHFSImage(t, image)
	payload, errObj := unwrapPair(t, HFSVerify(handle))
	if errObj != nil {
		t.Fatalf("hfs_verify: %s", errObj.Inspect())
	}
	result := payload.(*object.Hash)
	if failed := mustHashIntValue(t, result, "checks_failed"); failed != 0 {
		t.Errorf("a volume with no attributes tree failed %d checks: %s", failed, result.Inspect())
	}
	for _, f := range mustHashArrayValue(t, result, "findings") {
		if mustHashStringValue(t, f.(*object.Hash), "severity") == "critical" {
			t.Errorf("a critical finding on a healthy volume: %s", f.Inspect())
		}
	}
}
