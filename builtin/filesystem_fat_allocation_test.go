package builtin

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// buildFAT16DeletedDirImage adds to the deleted-scan image a deleted directory,
// OLDDIR in cluster 7, holding a deleted file, GONE2.TXT. The walk descends
// into OLDDIR and finds GONE2.TXT there; cluster 7 is free and unreferenced,
// so the orphan sweep finds the same record again.
func buildFAT16DeletedDirImage(t *testing.T) []byte {
	t.Helper()
	image := buildFAT16DeletedImage(t)
	firstFAT := fatDeletedReserved * fatTestSectorSize
	fatLen := fatDeletedFATSectors * fatTestSectorSize
	for _, base := range []int{firstFAT, firstFAT + fatLen} {
		fat := image[base : base+fatLen]
		putUint16LE(fat, 7*2, 0)
		putUint16LE(fat, 10*2, 0)
	}
	root := image[fatDeletedRootOffset:]
	writeFATDirEntry(root[128:], "OLDDIR     ", 0x10, 7, 0)
	root[128] = 0xE5
	dir := image[fatRecoverClusterOffset(7):]
	writeFATDirEntry(dir[0:], ".          ", 0x10, 7, 0)
	writeFATDirEntry(dir[32:], "..         ", 0x10, 0, 0)
	writeFATDirEntry(dir[64:], "GONE2   TXT", 0x20, 10, 100)
	dir[64] = 0xE5
	at := fatRecoverClusterOffset(10)
	copy(image[at:at+fatTestSectorSize], bytes.Repeat([]byte{'G'}, fatTestSectorSize))
	return image
}

// TestADeletedDirectorysChildIsListedOnce is M26-FS2-015's regression test.
// GONE2.TXT is one record on disk. The walk reported it under the deleted
// directory's path and the orphan sweep reported it again under $OrphanFiles,
// both with the same entry_offset, and entry_count counted it twice.
func TestADeletedDirectorysChildIsListedOnce(t *testing.T) {
	session := openRealFATDeletedSession(t, buildFAT16DeletedDirImage(t), 0)
	scan, err := session.ScanDeleted()
	if err != nil {
		t.Fatalf("ScanDeleted: %v", err)
	}

	offsets := map[int64]int{}
	var gone []fsDeletedEntry
	for _, e := range scan.Entries {
		if e.EntryOffset >= 0 {
			offsets[e.EntryOffset]++
		}
		if strings.HasSuffix(strings.ToUpper(e.Name), "ONE2.TXT") {
			gone = append(gone, e)
		}
	}
	for offset, n := range offsets {
		if n > 1 {
			t.Errorf("entry_offset %d is reported %d times", offset, n)
		}
	}
	if scan.EntryCount != int64(len(scan.Entries)) {
		t.Errorf("entry_count %d for %d rows", scan.EntryCount, len(scan.Entries))
	}
	if len(gone) != 1 {
		t.Fatalf("GONE2.TXT is listed %d times: %+v", len(gone), gone)
	}
	if gone[0].Source != fsDeletedSourceDirectory || !strings.Contains(strings.ToUpper(gone[0].Path), "LDDIR") {
		t.Errorf("the row kept is not the directory's: %+v", gone[0])
	}
	if !strings.Contains(strings.Join(gone[0].Reasons, " "), fsDeletedSourceOrphanScan) {
		t.Errorf("the row does not say the sweep found it too: %q", gone[0].Reasons)
	}
}

// TestAnAssumedRunIsCheckedClusterByCluster is M26-FS2-004's regression test.
// ONE.TXT records 2048 bytes from cluster 3, and cluster 4 has since been given
// to another file. Assuming contiguity synthesises clusters 3 to 6, and the
// recovery reported the whole run cross-referenced and free on the strength of
// cluster 3 alone -- with cluster 4's bytes, another file's, in the output.
func TestAnAssumedRunIsCheckedClusterByCluster(t *testing.T) {
	session := openRealFATDeletedSession(t, buildFAT16RecoverableImage(t), 0)
	scan, err := session.ScanDeleted()
	if err != nil {
		t.Fatalf("ScanDeleted: %v", err)
	}
	recovery, err := session.RecoverDeleted(indexOfScannedEntry(t, scan, "ONE.TXT"), true)
	if err != nil {
		t.Fatalf("RecoverDeleted: %v", err)
	}
	if !recovery.Assumed {
		t.Fatalf("the recovery did not assume a run; the fixture is not what this test needs")
	}
	if !recovery.AllocationChecked || !recovery.Reallocated {
		t.Errorf("an assumed run over an allocated cluster reported checked=%v reallocated=%v",
			recovery.AllocationChecked, recovery.Reallocated)
	}
	if caveats := strings.Join(recoveryCaveats(recovery, recovery.Length), "\n"); !strings.Contains(caveats, "cluster 4") {
		t.Errorf("no caveat names cluster 4:\n%s", caveats)
	}
}

// xfatVolBitmapEntry is the allocation bitmap's directory entry: its first
// cluster and its length in bytes. One byte covers clusters 2 to 9.
func xfatVolBitmapEntry(cluster uint32, length uint64) []byte {
	entry := make([]byte, 32)
	entry[0] = 0x81
	binary.LittleEndian.PutUint32(entry[20:24], cluster)
	binary.LittleEndian.PutUint64(entry[24:32], length)
	return entry
}

// buildExFATShortBitmapVolume is an exFAT volume of 5000 512-byte clusters
// whose allocation bitmap needs 625 bytes -- two clusters -- and whose chain
// ends after the first. The walk reads what bitmap there is; a deleted file at
// cluster 4500 lies past it, so its allocation cannot be read.
func buildExFATShortBitmapVolume() []byte {
	const sector, clusters, fatOffset, fatSectors, dataOffset = 512, 5000, 24, 40, 64
	volSectors := dataOffset + clusters
	img := make([]byte, volSectors*sector)
	copy(img[0:3], []byte{0xEB, 0x76, 0x90})
	copy(img[3:11], "EXFAT   ")
	binary.LittleEndian.PutUint64(img[0x48:], uint64(volSectors))
	binary.LittleEndian.PutUint32(img[0x50:], fatOffset)
	binary.LittleEndian.PutUint32(img[0x54:], fatSectors)
	binary.LittleEndian.PutUint32(img[0x58:], dataOffset)
	binary.LittleEndian.PutUint32(img[0x5C:], clusters)
	binary.LittleEndian.PutUint32(img[0x60:], 2)
	binary.LittleEndian.PutUint32(img[0x64:], 0xCAFEBABE)
	binary.LittleEndian.PutUint16(img[0x68:], 0x0100)
	img[0x6C], img[0x6D], img[0x6E] = 9, 0, 1 // 512-byte sectors, one a cluster
	img[0x1FE], img[0x1FF] = 0x55, 0xAA
	fat := img[fatOffset*sector:]
	binary.LittleEndian.PutUint32(fat[0:], 0xFFFFFFF8)
	binary.LittleEndian.PutUint32(fat[4:], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(fat[8:], 0xFFFFFFFF)  // the root, cluster 2
	binary.LittleEndian.PutUint32(fat[12:], 0xFFFFFFFF) // the bitmap ends after cluster 3
	cluster := func(n int) []byte { return img[dataOffset*sector+(n-2)*sector:] }
	copy(cluster(2)[0:], xfatVolBitmapEntry(3, (clusters+7)/8))
	copy(cluster(2)[32:], xfatVolEntrySet("gone.txt", true, 4500, 5))
	cluster(3)[0] = 0x03 // clusters 2 and 3 in use
	copy(cluster(4500), "GONE!")
	return img
}

// TestAnExFATEntryTheBitmapCannotAnswerForIsNotChecked is M26-FS2-017's
// regression test. gone.txt's first cluster lies past the bitmap the volume
// holds, so its allocation cannot be read. allocation_checked came from the
// record's AllocationPossible flag -- whether its cluster fields mean anything
// -- and read true, beside a reallocated false that nobody had looked for.
func TestAnExFATEntryTheBitmapCannotAnswerForIsNotChecked(t *testing.T) {
	handle := openVolumeWith(t, buildExFATShortBitmapVolume(), XFATOpen, XFATClose)

	payload, errObj := unwrapPair(t, XFATDeleted(handle))
	if errObj != nil {
		t.Fatalf("xfat_deleted: %s", errObj.Inspect())
	}
	var gone *object.Hash
	for _, e := range hashValueByKey(payload.(*object.Hash), "entries").(*object.Array).Elements {
		if row := e.(*object.Hash); mustHashStringValue(t, row, "name") == "gone.txt" {
			gone = row
		}
	}
	if gone == nil {
		t.Fatalf("xfat_deleted did not report gone.txt: %s", payload.Inspect())
	}
	if mustHashBoolValue(t, gone, "allocation_checked") {
		t.Errorf("an entry whose allocation could not be read reports allocation_checked: %s", gone.Inspect())
	}

	dest := filepath.Join(t.TempDir(), "gone.txt")
	recovered, errObj := unwrapPair(t, XFATRecoverFile(handle, mustHashValue(t, gone, "index"), stringObj(dest)))
	if errObj != nil {
		t.Fatalf("xfat_recover_file: %s", errObj.Inspect())
	}
	if mustHashBoolValue(t, recovered.(*object.Hash), "allocation_checked") {
		t.Errorf("the recovery reports allocation_checked for a run the bitmap could not answer for")
	}
}

// libxfat files what its carve finds under a directory of its own invention,
// /$OrphanFiles. That directory is not a record on the volume, and its path
// starts with the carved prefix, so xfat_deleted reported it as a carved
// deleted entry of cluster 0.
func TestTheCarveRootIsNotADeletedRecord(t *testing.T) {
	handle := openVolumeWith(t, buildExFATShortBitmapVolume(), XFATOpen, XFATClose)
	payload, errObj := unwrapPair(t, XFATDeleted(handle))
	if errObj != nil {
		t.Fatalf("xfat_deleted: %s", errObj.Inspect())
	}
	for _, e := range hashValueByKey(payload.(*object.Hash), "entries").(*object.Array).Elements {
		if row := e.(*object.Hash); mustHashStringValue(t, row, "path") == "/$OrphanFiles" {
			t.Errorf("the carve's own root is reported as a deleted record: %s", row.Inspect())
		}
	}
}
