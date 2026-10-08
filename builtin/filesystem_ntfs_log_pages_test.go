package builtin

import (
	"testing"

	libntfs "github.com/aoiflux/libntfs"

	"mutant/object"
)

// buildNTFSVolumeWithLog is buildNTFSVolume(2) given a $LogFile, record 2, of
// two 4 KiB pages in clusters 12 and 13: the first blank, the second a record
// page carrying no records, whose update sequence fails in its fourth sector
// when torn is set -- the mark a write left half done.
func buildNTFSVolumeWithLog(torn bool) []byte {
	image := buildNTFSVolume(2)
	copy(image[ntfsVolMFTCluster*ntfsVolClusterSize+2*ntfsVolRecordSize:],
		ntfsVolRecord(libntfs.MFTFlagInUse, "$LogFile", 5, 2*ntfsVolClusterSize, ntfsVolData(12, 2, 2*ntfsVolClusterSize)))
	page := image[13*ntfsVolClusterSize : 14*ntfsVolClusterSize]
	libntfs.WriteUint32LE(page, 0, libntfs.LogRecordPageMagic)
	libntfs.WriteUint16LE(page, 4, 0x28) // update sequence array offset
	libntfs.WriteUint16LE(page, 6, 9)    // its count: the number and one word per sector
	const usn = 0x0101
	libntfs.WriteUint16LE(page, 0x28, usn)
	for sector := 1; sector <= 8; sector++ {
		libntfs.WriteUint16LE(page, sector*libntfs.UpdateSequenceStride-2, usn)
	}
	if torn {
		libntfs.WriteUint16LE(page, 4*libntfs.UpdateSequenceStride-2, 0x0202)
	}
	return image
}

// TestATornLogPageIsNotPassedOverUnseen is the regression test for the
// $LogFile scans' silent drop. libntfs leaves a record page whose update
// sequence fails out of its walk, whole and without a word, and the scans said
// complete over it; ntfs_log_records' own summary said such pages "vanish
// without trace".
func TestATornLogPageIsNotPassedOverUnseen(t *testing.T) {
	for name, scanOf := range map[string]func(object.Object) object.Object{
		"ntfs_log_records":      func(h object.Object) object.Object { return NtfsLogRecords(h) },
		"ntfs_log_transactions": func(h object.Object) object.Object { return NtfsLogTransactions(h) },
	} {
		for _, torn := range []bool{false, true} {
			payload, errObj := unwrapPair(t, scanOf(openNTFSVolume(t, buildNTFSVolumeWithLog(torn))))
			if errObj != nil {
				t.Fatalf("%s: %s", name, errObj.Inspect())
			}
			scan := payload.(*object.Hash)
			if !mustHashBoolValue(t, scan, "present") {
				t.Fatalf("%s: the fixture's $LogFile is not present: %s", name, scan.Inspect())
			}
			flagged := hasCode(hashWarningCodes(t, scan), "log_pages_torn")
			if flagged != torn {
				t.Errorf("%s, torn page %v: log_pages_torn raised %v", name, torn, flagged)
			}
			if torn && mustHashBoolValue(t, scan, "complete") {
				t.Errorf("%s says complete over a page it left out: %s", name, scan.Inspect())
			}
		}
	}
}
