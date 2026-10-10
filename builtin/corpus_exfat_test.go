package builtin

// Real-image tests: exFAT.
//
// WHERE THE GROUND TRUTH COMES FROM, AND WHICH TOOL NOT TO TRUST.
//
// The corpus carries oracle files for FAT and HFS and none for exFAT, so the
// numbers below were recorded here from exfatprogs 1.2.2 and from a decode of
// the volume's own boot sector and root directory. The commands are given so
// they can be re-derived rather than believed:
//
//	cp img1_exfat.dd <scratch>/          # fsck can repair; the corpus is read-only
//	fsck.exfat -n -v <scratch>/img1_exfat.dd
//	  -> clean. directories 52, files 677
//
// dump.exfat from the same package is NOT an oracle for this volume, and a
// future reader reaching for it should know why before trusting its output. It
// reads the three metadata entries positionally -- slot 0 the volume label,
// slot 1 the allocation bitmap, slot 2 the up-case table. This volume's root
// directory holds, in order: 0x83 volume label, then entry type 0x20, then 0x81
// allocation bitmap at cluster 2 length 3136, then 0x82 up-case table at
// cluster 3 length 5836, then the 0x85/0xC0/0xC1 set for one file. 0x20 is 0xA0
// -- the Volume GUID type -- with the in-use bit cleared, and exFAT puts
// 0x01..0x7F in the "unused, skip it" range. dump.exfat does not skip it, so it
// reports the dead entry as the bitmap (first cluster 0, length 0, and
// therefore "Free Clusters: 25088" of 25088 on a volume that has 18789
// allocated) and reports the real bitmap as the up-case table. fsck.exfat walks
// the tree instead and is right. TestARealExFATVolumeAllocationAgreesWithItsOwnBitmap
// settles the allocation figure from the bitmap bytes, which needs no reader at
// all.
//
// WHAT THIS CANNOT MEASURE. There is no per-file oracle for exFAT the way there
// is for FAT, and not for want of trying: exfatprogs ships no extraction tool,
// 7-Zip declines the format outright ("Cannot open the file as archive"), and
// looping the image to read it through the kernel needs root. So these tests
// compare geometry, allocation and what the volume holds by count, and they do
// not compare file contents. Per-file digests would need the volume mounted
// read-only, which is the owner's to run.
//
// THE REGRESSION THIS FILE EXISTS FOR. M26-FS1-020: until it was fixed, none of
// these tests could have run at all, because xfat_open refused both exFAT
// volumes in the corpus. See TestARealExFATVolumeOpensAlthoughItRecordsAPartitionOffset.

import (
	"math/bits"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"mutant/object"
)

// exfatOracle is what an independent reader and a boot-sector decode say about
// the corpus's exFAT volume.
//
// img1_exfat.dd and img2_exfat.dd are byte-identical -- confirmed by comparing
// them, not assumed from their size -- so one oracle serves both, and running
// both is also what would notice if that ever stopped being true.
type exfatOracleValues struct {
	label             string
	sectorSize        int64
	clusterSize       int64
	sectorsPerCluster int64
	clusterCount      int64
	volumeSerial      int64
	revision          string
	volumeDirty       bool
	mediaFailure      bool

	// clusterHeapByte is where cluster 2 begins: ClusterHeapOffset 4096
	// sectors times 512. The report calls it offset.
	clusterHeapByte int64

	// recordedPartitionSector is the PartitionOffset the boot sector records
	// about itself, and openedAtByte is where the volume actually is. These
	// disagree, which is the whole subject of M26-FS1-020.
	recordedPartitionSector int64
	openedAtByte            int64

	// bitmapByte and bitmapLength locate the allocation bitmap, from the 0x81
	// root entry: first cluster 2, data length 3136 bytes = 25088 bits = one
	// bit per cluster.
	bitmapByte   int64
	bitmapLength int64

	// fsck.exfat -n -v counts live entries only, and counts the root directory
	// among the directories.
	fsckDirectories int
	fsckFiles       int

	// deletedEntries is OUR count, not an independent one: fsck reports only
	// what the filesystem still says is there, so nothing outside mutant has
	// counted these. It is pinned so that a change is noticed, and it is
	// labelled here so it is never mistaken for third-party ground truth.
	deletedEntries int
}

var exfatOracle = exfatOracleValues{
	label:                   "mb100",
	sectorSize:              512,
	clusterSize:             4096,
	sectorsPerCluster:       8,
	clusterCount:            25088,
	volumeSerial:            2145363060, // 0x7fdfa474
	revision:                "1.0",      // FileSystemRevision 0x0100
	volumeDirty:             true,       // VolumeFlags 0x0002
	mediaFailure:            false,
	clusterHeapByte:         2097152,
	recordedPartitionSector: 2048,
	openedAtByte:            0,
	bitmapByte:              2097152,
	bitmapLength:            3136,
	fsckDirectories:         52,
	fsckFiles:               677,
	deletedEntries:          5,
}

var exfatCorpusVolumes = []string{"img1_exfat.dd", "img2_exfat.dd"}

func openCorpusXFAT(t *testing.T, image string) string {
	t.Helper()

	payload, errObj := unwrapPair(t, XFATOpen(stringObj(image)))
	if errObj != nil {
		t.Fatalf("xfat_open(%s): %s", image, errObj.Inspect())
	}
	openHash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("xfat_open payload is not HASH. got=%T", payload)
	}
	handle := mustHashStringValue(t, openHash, "handle")
	t.Cleanup(func() { XFATClose(stringObj(handle)) })
	return handle
}

// xfatReportVolume is the volume sub-hash of an xfat_report, with its warning
// codes beside it.
func xfatReportVolume(t *testing.T, handle string) (*object.Hash, map[string]bool) {
	t.Helper()

	payload, errObj := unwrapPair(t, XFATReport(stringObj(handle)))
	if errObj != nil {
		t.Fatalf("xfat_report: %s", errObj.Inspect())
	}
	report, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("xfat_report payload is not HASH. got=%T", payload)
	}

	volume, ok := hashField(t, report, "volume").(*object.Hash)
	if !ok {
		t.Fatalf("xfat_report volume is not HASH")
	}

	codes := map[string]bool{}
	if raised, ok := hashField(t, report, "warning_codes").(*object.Array); ok {
		for _, el := range raised.Elements {
			code, ok := el.(*object.String)
			if !ok {
				t.Fatalf("a warning code is not STRING. got=%T", el)
			}
			codes[code.Value] = true
		}
	}
	return volume, codes
}

// TestARealExFATVolumeOpensAlthoughItRecordsAPartitionOffset is the regression
// for M26-FS1-020.
//
// Both exFAT volumes in the corpus record that their partition began at sector
// 2048 -- the ordinary consequence of 1 MiB alignment -- and both are handed
// over as a file whose byte 0 is the volume, which is what imaging a partition
// produces. libxfat cross-checks the recorded value against the byte the volume
// was opened at, and realXFATBackend.Open used to pass neither of the two
// options that resolve the case, so every one of the sixteen xfat_* builtins
// was unreachable for an image of this shape: 0 of 5 expressible openings
// succeeded. exFAT section 3.1.3 makes PartitionOffset informational and lets
// an implementation ignore it, which is what exfatprogs does.
//
// The two numbers are not discarded along with the refusal. That is the half of
// this test that would still fail if the fix had simply stopped checking.
func TestARealExFATVolumeOpensAlthoughItRecordsAPartitionOffset(t *testing.T) {
	compared := 0
	for _, rel := range exfatCorpusVolumes {
		t.Run(rel, func(t *testing.T) {
			image, ok := corpusFile(t, rel)
			if !ok {
				return
			}
			compared++

			handle := openCorpusXFAT(t, image)
			volume, codes := xfatReportVolume(t, handle)

			if got := mustHashIntValue(t, volume, "partition_offset"); got != exfatOracle.recordedPartitionSector {
				t.Errorf("the volume records that its partition began at sector %d, the report says %d",
					exfatOracle.recordedPartitionSector, got)
			}
			if got := mustHashIntValue(t, volume, "base"); got != exfatOracle.openedAtByte {
				t.Errorf("the volume was opened at byte %d, the report says %d",
					exfatOracle.openedAtByte, got)
			}
			if !codes[fsReportWarnPartitionOffset] {
				raised := make([]string, 0, len(codes))
				for code := range codes {
					raised = append(raised, code)
				}
				sort.Strings(raised)
				t.Errorf("sector %d and byte %d disagree and nothing said so: the report raised %v, "+
					"and dropping the signal is what skipping the cross-check must not cost",
					exfatOracle.recordedPartitionSector, exfatOracle.openedAtByte, raised)
			}
		})
	}
	if *corpusDir != "" {
		t.Logf("%d exFAT volumes opened despite a recorded partition offset", compared)
	}
	if *corpusDir != "" && compared == 0 {
		t.Errorf("-corpus.dir is %q and not one exFAT volume was opened: the suite would have "+
			"reported success while measuring nothing", *corpusDir)
	}
}

// TestARealExFATVolumeReportsItsOwnGeometry compares the report's volume fields
// against exfatprogs and the boot sector.
func TestARealExFATVolumeReportsItsOwnGeometry(t *testing.T) {
	compared := 0
	for _, rel := range exfatCorpusVolumes {
		t.Run(rel, func(t *testing.T) {
			image, ok := corpusFile(t, rel)
			if !ok {
				return
			}
			compared++

			volume, _ := xfatReportVolume(t, openCorpusXFAT(t, image))

			for _, check := range []struct {
				field string
				want  int64
			}{
				{"sector_size", exfatOracle.sectorSize},
				{"block_size", exfatOracle.clusterSize},
				{"sectors_per_cluster", exfatOracle.sectorsPerCluster},
				{"cluster_count", exfatOracle.clusterCount},
				{"volume_serial", exfatOracle.volumeSerial},
				{"offset", exfatOracle.clusterHeapByte},
			} {
				if got := mustHashIntValue(t, volume, check.field); got != check.want {
					t.Errorf("%s: mutant says %d, the independent reader says %d", check.field, got, check.want)
				}
			}
			if got := mustHashStringValue(t, volume, "volume_label"); got != exfatOracle.label {
				t.Errorf("mutant labels this volume %q, the independent reader labels it %q", got, exfatOracle.label)
			}
			if got := mustHashStringValue(t, volume, "revision"); got != exfatOracle.revision {
				t.Errorf("mutant reads revision %q, the boot sector records %q", got, exfatOracle.revision)
			}
			// The dirty bit is the one geometry field that changes what the
			// rest of the document is worth, so it is checked rather than
			// logged: a volume that was not cleanly unmounted may have a
			// bitmap and directory entries that disagree.
			if got := mustHashBoolValue(t, volume, "volume_dirty"); got != exfatOracle.volumeDirty {
				t.Errorf("volume_dirty is %v, VolumeFlags 0x0002 says %v", got, exfatOracle.volumeDirty)
			}
			if got := mustHashBoolValue(t, volume, "media_failure"); got != exfatOracle.mediaFailure {
				t.Errorf("media_failure is %v, the boot sector says %v", got, exfatOracle.mediaFailure)
			}

			clusterBytes := mustHashIntValue(t, volume, "cluster_count") * mustHashIntValue(t, volume, "block_size")
			size, err := os.Stat(image)
			if err != nil {
				t.Fatalf("stat %s: %v", image, err)
			}
			if heap := exfatOracle.clusterHeapByte; clusterBytes+heap > size.Size() {
				t.Errorf("mutant claims %d bytes of clusters beginning at byte %d, which runs past the "+
					"end of a %d byte image", clusterBytes, heap, size.Size())
			}
		})
	}
	if *corpusDir != "" {
		t.Logf("%d exFAT volumes' geometry compared against an independent reader", compared)
	}
	if *corpusDir != "" && compared == 0 {
		t.Errorf("-corpus.dir is %q and not one exFAT volume's geometry was compared", *corpusDir)
	}
}

// exfatWalked is what one recursive listing of a volume reached, bucketed by
// the bits each row carries.
type exfatWalked struct {
	liveDirs, liveFiles       int
	specialDirs, specialFiles int
	deletedRows               int
	specialNames              []string
	deletedNames              []string
}

// xfatWalk lists the whole volume and buckets what it finds.
//
// The three buckets are the reason this test can be compared with fsck at all.
// A listing reports deleted entries at the slots they occupy, and libxfat
// presents the filesystem's own structures as entries too -- $BitMap and
// $UpCase, which have real directory entries and real clusters, and $FAT1,
// $MBR and $OrphanFiles, which are synthesised and carry virtual. fsck counts
// neither kind. So special and deleted come out separately and what remains is
// what both readers are talking about.
func xfatWalk(t *testing.T, handle string) exfatWalked {
	t.Helper()

	var out exfatWalked
	seen := map[string]bool{}

	var walk func(path string, depth int)
	walk = func(path string, depth int) {
		if seen[path] {
			return
		}
		if depth > 64 {
			t.Fatalf("the listing nests deeper than 64 at %s, which a 100 MB volume should not", path)
		}
		seen[path] = true

		payload, errObj := unwrapPair(t, XFATListFiles(stringObj(handle), stringObj(path)))
		if errObj != nil {
			t.Fatalf("xfat_list_files(%s): %s", path, errObj.Inspect())
		}
		rows, ok := payload.(*object.Array)
		if !ok {
			t.Fatalf("xfat_list_files payload is not ARRAY. got=%T", payload)
		}

		for _, el := range rows.Elements {
			row, ok := el.(*object.Hash)
			if !ok {
				t.Fatalf("a listing row is not HASH. got=%T", el)
			}
			name := mustHashStringValue(t, row, "name")
			child := mustHashStringValue(t, row, "path")
			isDir := mustHashBoolValue(t, row, "is_dir")

			switch {
			case mustHashBoolValue(t, row, "deleted"):
				out.deletedRows++
				out.deletedNames = append(out.deletedNames, name)
			case mustHashBoolValue(t, row, "special"):
				if isDir {
					out.specialDirs++
				} else {
					out.specialFiles++
				}
				out.specialNames = append(out.specialNames, name)
			case isDir:
				out.liveDirs++
			default:
				out.liveFiles++
			}

			if isDir && child != "" && child != path {
				walk(child, depth+1)
			}
		}
	}
	walk("/", 0)

	sort.Strings(out.specialNames)
	sort.Strings(out.deletedNames)
	return out
}

// TestARealExFATVolumeHoldsWhatAnIndependentReaderCounted reconciles a full
// recursive listing with fsck.exfat's counts.
//
// It has to reconcile rather than compare, and both adjustments are forced by
// what the two readers mean. fsck counts the root directory among its
// directories and a walk of the root's children cannot see it, so one is added.
// fsck counts live user entries only, so the filesystem's own structures and
// the deleted entries come out. Nothing else is subtracted: if the remainder
// did not then land on fsck's figures exactly, the difference would be a real
// disagreement about what the volume holds.
func TestARealExFATVolumeHoldsWhatAnIndependentReaderCounted(t *testing.T) {
	compared := 0
	for _, rel := range exfatCorpusVolumes {
		t.Run(rel, func(t *testing.T) {
			image, ok := corpusFile(t, rel)
			if !ok {
				return
			}
			compared++

			walked := xfatWalk(t, openCorpusXFAT(t, image))

			if got := walked.liveDirs + 1; got != exfatOracle.fsckDirectories {
				t.Errorf("mutant reaches %d directories below the root, so %d with it, and fsck.exfat "+
					"counts %d", walked.liveDirs, got, exfatOracle.fsckDirectories)
			}
			if walked.liveFiles != exfatOracle.fsckFiles {
				t.Errorf("mutant reaches %d live user files and fsck.exfat counts %d; the walk also "+
					"saw %d of the filesystem's own entries %v and %d deleted entries",
					walked.liveFiles, exfatOracle.fsckFiles,
					walked.specialDirs+walked.specialFiles, walked.specialNames, walked.deletedRows)
			}
			if walked.deletedRows != exfatOracle.deletedEntries {
				t.Errorf("mutant reports %d deleted entries %v where it reported %d when this test was "+
					"written; no independent reader counts these, so this is a change to look at "+
					"rather than a disagreement", walked.deletedRows, walked.deletedNames,
					exfatOracle.deletedEntries)
			}
			t.Logf("%d live directories plus the root, %d live files, %d filesystem entries %v, "+
				"%d deleted %v", walked.liveDirs, walked.liveFiles,
				walked.specialDirs+walked.specialFiles, walked.specialNames,
				walked.deletedRows, walked.deletedNames)
		})
	}
	if *corpusDir != "" {
		t.Logf("%d exFAT volumes' contents reconciled with an independent reader", compared)
	}
	if *corpusDir != "" && compared == 0 {
		t.Errorf("-corpus.dir is %q and not one exFAT volume's contents were counted", *corpusDir)
	}
}

// TestARealExFATVolumeAllocationAgreesWithItsOwnBitmap checks the allocated
// cluster count against the bitmap on the volume.
//
// This is the one check here that needs no reader at all: the allocation bitmap
// is one bit per cluster, so the number of allocated clusters is the number of
// set bits in it, and counting them is arithmetic over bytes read at a fixed
// offset. It is worth having precisely because the obvious tool disagrees --
// dump.exfat reports every cluster free on this volume, for the reason given at
// the top of this file -- and a figure that can be settled from the bytes should
// not be taken from a reader that can be wrong about it.
func TestARealExFATVolumeAllocationAgreesWithItsOwnBitmap(t *testing.T) {
	compared := 0
	for _, rel := range exfatCorpusVolumes {
		t.Run(rel, func(t *testing.T) {
			image, ok := corpusFile(t, rel)
			if !ok {
				return
			}
			compared++

			file, err := os.Open(image)
			if err != nil {
				t.Fatalf("open %s: %v", image, err)
			}
			defer file.Close()

			bitmap := make([]byte, exfatOracle.bitmapLength)
			if _, err := file.ReadAt(bitmap, exfatOracle.bitmapByte); err != nil {
				t.Fatalf("read the allocation bitmap at byte %d: %v", exfatOracle.bitmapByte, err)
			}
			if want := exfatOracle.clusterCount; int64(len(bitmap))*8 != want {
				t.Fatalf("the bitmap is %d bytes = %d bits, for a volume of %d clusters: one of the "+
					"two numbers in this test's oracle is wrong", len(bitmap), len(bitmap)*8, want)
			}

			allocated := 0
			for _, b := range bitmap {
				allocated += bits.OnesCount8(b)
			}

			volume, _ := xfatReportVolume(t, openCorpusXFAT(t, image))
			if got := mustHashIntValue(t, volume, "allocated_clusters"); got != int64(allocated) {
				t.Errorf("mutant reports %d allocated clusters and the volume's own bitmap has %d bits "+
					"set", got, allocated)
			}
			t.Logf("%d of %d clusters allocated, counted from the bitmap at byte %d",
				allocated, exfatOracle.clusterCount, exfatOracle.bitmapByte)
		})
	}
	if *corpusDir != "" {
		t.Logf("%d exFAT volumes' allocation checked against their own bitmap", compared)
	}
	if *corpusDir != "" && compared == 0 {
		t.Errorf("-corpus.dir is %q and not one exFAT volume's allocation was checked", *corpusDir)
	}
}

// TestAnExplicitExFATOffsetIsStillHonoured pins the other half of the
// M26-FS1-020 fix.
//
// The cross-check is skipped only when the caller gave no offset, because then
// there is nothing to compare the recorded value against. An offset the caller
// did give is still where the volume is read from, and this is what says so:
// opening this volume at the byte it claims its partition began at finds no
// boot record there, because the volume is at byte 0. A fix that had made
// xfat_open ignore its offset argument would open happily here.
func TestAnExplicitExFATOffsetIsStillHonoured(t *testing.T) {
	image, ok := corpusFile(t, exfatCorpusVolumes[0])
	if !ok {
		return
	}

	recordedByte := exfatOracle.recordedPartitionSector * exfatOracle.sectorSize
	payload, errObj := unwrapPairNoFatal(XFATOpen(stringObj(image), intObj(recordedByte)))
	if errObj == nil {
		if hash, isHash := payload.(*object.Hash); isHash {
			XFATClose(stringObj(mustHashStringValue(t, hash, "handle")))
		}
		t.Fatalf("xfat_open(%s, %d) opened a volume: there is no exFAT boot record at byte %d, so an "+
			"explicit offset is being ignored", filepath.Base(image), recordedByte, recordedByte)
	}
	t.Logf("an explicit offset of %d is honoured and refused: %s", recordedByte, errObj.Message)
}
