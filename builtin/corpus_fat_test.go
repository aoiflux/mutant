package builtin

// Real-image tests for the FAT builtins. See corpus_oracle_test.go for why
// these exist and why the corpus path arrives as a flag.

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"mutant/object"
)

// fatCorpusVolumes are the volumes with a FAT oracle beside them.
//
// The five geometry volumes and the five content volumes are listed with what
// only each of them covers, because a table of file names says nothing about
// why fourteen volumes are needed instead of one. Every entry here was written
// by dosfstools or mtools, and every oracle beside it by 7-Zip; none of the
// three shares code or reasoning with libfat.
var fatCorpusVolumes = []struct {
	rel  string
	what string
}{
	{"fat_synth/fat12_b512.img", "FAT12 at all: no other image in the corpus is FAT12, and its 12-bit entries straddle byte and sector boundaries"},
	{"fat_synth/fat12_b4096.img", "FAT12 where one sector is a whole cluster, so the table spans a different sector count"},
	{"fat_synth/fat16_b1024.img", "a sector that is not 512 bytes"},
	{"fat_synth/fat16_bigroot.img", "a 1024-entry fixed root region, twice the usual"},
	{"fat_synth/fat32_onefat.img", "one FAT rather than two"},
	{"fat_synth/fat12_deleted.img", "deleted records on FAT12, in the fixed root region rather than in a cluster"},
	{"fat_synth/fat16_deleted.img", "deleted records on FAT16, two of three with long-name slots orphaned by the deletion"},
	{"fat_synth/fat32_deleted.img", "deleted records on FAT32, read back through a 32-bit table"},
	{"fat_synth/fat16_frag.img", "a fragmented regular file: 30 chunks written, every other one deleted, then a 2 MB file into the holes"},
	{"fat_synth/fat32_frag.img", "the same on FAT32, which fragments only when the volume is nearly full first"},
	{"fat_synth/fat32_relabel.img", "a boot sector label reading NO NAME while the root directory says REALNAME"},
	{"fat_synth/fat32_mirror.img", "two FATs that disagree"},
	{"fat_synth/fat32_orphan.img", "a directory whose record is deleted and whose clusters are released while its contents stay intact"},
	{"img9_fat16.dd", "a real 512 MB FAT16 volume, 1986 files"},
	{"img10_fat32.dd", "a real 512 MB FAT32 volume, 1724 files"},
}

// TestARealFATVolumeListsWhatAnIndependentReaderSees walks every volume with
// the real backend in place and requires mutant's answer to match 7-Zip's,
// entry for entry and byte for byte.
//
// Three things are compared and all three matter: the set of paths, because a
// parser that loses a directory loses everything under it; each file's size
// and 8.3 short name, because those are decoded fields rather than derived
// ones; and each file's content digest, because a size read from the right
// offset proves nothing about the cluster chain that locates the bytes. The
// digest is the one that would catch a chain followed wrongly on the
// fragmented volumes, where every other reading looks correct.
func TestARealFATVolumeListsWhatAnIndependentReaderSees(t *testing.T) {
	compared := 0
	for _, volume := range fatCorpusVolumes {
		t.Run(filepath.Base(volume.rel), func(t *testing.T) {
			image, ok := corpusFile(t, volume.rel)
			if !ok {
				return
			}
			oraclePath, ok := corpusFile(t, volume.rel+".fat-oracle.tsv")
			if !ok {
				return
			}
			compared++
			t.Logf("what only this volume covers: %s", volume.what)

			oracle := readFATOracle(t, oraclePath)
			handle := openCorpusFAT(t, image)
			dirs, files := fatLiveTree(t, handle)

			comparePathSets(t, "directories", dirs, oracle.Dirs)

			oraclePaths := make([]string, 0, len(oracle.Files))
			for _, want := range oracle.Files {
				oraclePaths = append(oraclePaths, want.Path)
			}
			gotPaths := make([]string, 0, len(files))
			for path := range files {
				gotPaths = append(gotPaths, path)
			}
			sort.Strings(gotPaths)
			comparePathSets(t, "files", gotPaths, oraclePaths)

			hashedFiles, hashedBytes, skippedDigests := 0, int64(0), 0
			for _, want := range oracle.Files {
				got, ok := files[want.Path]
				if !ok {
					continue // already reported by comparePathSets
				}
				if got.size != want.Size {
					t.Errorf("%s: mutant says %d bytes, the independent reader says %d",
						want.Path, got.size, want.Size)
				}
				if got.shortName != want.ShortName {
					t.Errorf("%s: mutant says the 8.3 name is %q, the independent reader says %q",
						want.Path, got.shortName, want.ShortName)
				}
				if want.SHA256 == "-" {
					skippedDigests++
					continue
				}
				digest, size, located, truncated := fatHashOf(t, handle, want.Path)
				if digest != want.SHA256 {
					t.Errorf("%s: mutant's content hashes to %s, the independent reader's to %s",
						want.Path, digest, want.SHA256)
					continue
				}
				// A live file's bytes are all locatable by definition: the
				// chain that holds them has not been freed. located short of
				// size, or truncated set, on a file whose digest matched would
				// mean the two numbers beside the content describe something
				// else, and a caller reads those numbers to decide whether to
				// trust the content.
				if located != size || truncated {
					t.Errorf("%s: the content matched but the report around it does not: size %d, located %d, truncated %v",
						want.Path, size, located, truncated)
				}
				hashedFiles++
				hashedBytes += size
			}
			t.Logf("%d directories, %d files, %d content digests over %d bytes, %d digests the oracle does not carry",
				len(oracle.Dirs), len(oracle.Files), hashedFiles, hashedBytes, skippedDigests)
		})
	}
	if *corpusDir != "" && compared == 0 {
		t.Errorf("-corpus.dir is %q and not one volume was compared: the suite would have reported "+
			"success while measuring nothing", *corpusDir)
	}
}

// TestARealFATVolumeReportsItsOwnGeometry compares the volume's own fields,
// which the listing never touches.
//
// Four of the oracle's five volume columns are compared. The fifth, physical
// size, is deliberately not: 7-Zip reports the size of the image it opened,
// while mutant reports a data-cluster count, and the two differ by the
// reserved sectors and the tables. It is used as a bound instead -- a volume
// claiming more cluster bytes than the image holds would be caught -- because
// an assertion that two different quantities are equal is worse than none.
func TestARealFATVolumeReportsItsOwnGeometry(t *testing.T) {
	compared := 0
	for _, volume := range fatCorpusVolumes {
		t.Run(filepath.Base(volume.rel), func(t *testing.T) {
			image, ok := corpusFile(t, volume.rel)
			if !ok {
				return
			}
			oraclePath, ok := corpusFile(t, volume.rel+".fat-oracle.tsv")
			if !ok {
				return
			}
			compared++

			oracle := readFATOracle(t, oraclePath)
			handle := openCorpusFAT(t, image)

			payload, errObj := unwrapPair(t, FatMetadata(stringObj(handle), stringObj("/")))
			if errObj != nil {
				t.Fatalf("fat_metadata(/): %s", errObj.Inspect())
			}
			meta, ok := payload.(*object.Hash)
			if !ok {
				t.Fatalf("fat_metadata payload is not HASH. got=%T", payload)
			}

			if got := mustHashStringValue(t, meta, "filesystem"); got != oracle.FileSystem {
				t.Errorf("mutant calls this %s, the independent reader calls it %s", got, oracle.FileSystem)
			}
			// The relabel volume is the one this check exists for: its boot
			// sector says NO NAME and its root directory says REALNAME, and
			// the root directory is the one that wins.
			if got := mustHashStringValue(t, meta, "volume_label"); got != oracle.Label {
				t.Errorf("mutant labels this volume %q, the independent reader labels it %q", got, oracle.Label)
			}
			if got := mustHashIntValue(t, meta, "cluster_size"); got != oracle.ClusterSize {
				t.Errorf("mutant says the cluster is %d bytes, the independent reader says %d", got, oracle.ClusterSize)
			}
			if got := mustHashIntValue(t, meta, "bytes_per_sector"); got != oracle.SectorSize {
				t.Errorf("mutant says the sector is %d bytes, the independent reader says %d", got, oracle.SectorSize)
			}

			clusters := mustHashIntValue(t, meta, "cluster_count")
			clusterBytes := clusters * mustHashIntValue(t, meta, "cluster_size")
			if clusterBytes > oracle.PhysicalSize {
				t.Errorf("mutant claims %d data clusters of %d bytes, %d in all, inside a volume the "+
					"independent reader measures at %d bytes",
					clusters, oracle.ClusterSize, clusterBytes, oracle.PhysicalSize)
			}
		})
	}
	if *corpusDir != "" {
		t.Logf("%d volumes' geometry compared against an independent reader", compared)
	}
	if *corpusDir != "" && compared == 0 {
		t.Errorf("-corpus.dir is %q and not one volume's geometry was compared", *corpusDir)
	}
}

// TestAFATVolumeInsideAPartitionTableReadsTheRightPartition opens a FAT volume
// that is one partition of a 10 GB GPT image, by handing fat_open the
// partition hash the table builtins produced.
//
// This is the composition the table_ family exists for, and the failure it
// guards against is specific: opening at the right offset and then reading to
// the end of the disk, which reports a neighbouring partition's bytes as this
// volume's. An oracle recorded from that one partition is what can tell the
// difference, because a volume read past its own end is still internally
// consistent.
func TestAFATVolumeInsideAPartitionTableReadsTheRightPartition(t *testing.T) {
	image, ok := corpusFile(t, "img4_gpt.dd")
	if !ok {
		t.Skip("the GPT image is not in this copy of the corpus")
	}
	oraclePath, ok := corpusFile(t, "img4_gpt.dd.p3.fat-oracle.tsv")
	if !ok {
		t.Skip("the oracle for the GPT image's FAT partition is not in this copy of the corpus")
	}
	oracle := readFATOracle(t, oraclePath)

	payload, errObj := unwrapPair(t, TableOpen(stringObj(image)))
	if errObj != nil {
		t.Fatalf("table_open(%s): %s", image, errObj.Inspect())
	}
	tableHandle := mustHashStringValue(t, payload.(*object.Hash), "handle")
	t.Cleanup(func() { TableClose(stringObj(tableHandle)) })

	listed, errObj := unwrapPair(t, TableListPartitions(stringObj(tableHandle)))
	if errObj != nil {
		t.Fatalf("table_list_partitions: %s", errObj.Inspect())
	}
	partitions, ok := listed.(*object.Array)
	if !ok {
		t.Fatalf("table_list_partitions payload is not ARRAY. got=%T", listed)
	}

	// The volume is picked by slot_number and not by index, and the difference
	// matters: table_list_partitions maps the WHOLE disk, so its ten rows
	// include the protective MBR, both GPT headers, both copies of the table
	// and the unallocated tail, and index is a position in that map. Only four
	// of the ten are partitions, and slot_number is where each one sits in the
	// table, with -1 on everything that is not a partition. Reading index as a
	// partition number here picked the Microsoft reserved partition and opened
	// nothing; a script making the same mistake would read a neighbour's bytes
	// and report them as this volume's.
	//
	// The partition hash is then passed through whole rather than its start
	// byte copied out, which is the documented composition and the only form
	// that carries the length as well as the offset.
	const wantedSlot = 3
	var partition *object.Hash
	var slots []string
	for _, element := range partitions.Elements {
		entry, ok := element.(*object.Hash)
		if !ok {
			t.Fatalf("a partition is not HASH. got=%T", element)
		}
		slot := mustHashIntValue(t, entry, "slot_number")
		if slot < 0 {
			continue
		}
		slots = append(slots, fmt.Sprintf("%d (%s)", slot, mustHashStringValue(t, entry, "type_name")))
		if slot == wantedSlot {
			partition = entry
		}
	}
	if partition == nil {
		t.Fatalf("the image's table has no partition in slot %d, and the oracle was recorded from one; "+
			"the slots it does have are %s", wantedSlot, strings.Join(slots, ", "))
	}

	opened, errObj := unwrapPair(t, FatOpen(stringObj(image), partition))
	if errObj != nil {
		t.Fatalf("fat_open through the partition hash: %s", errObj.Inspect())
	}
	openHash := opened.(*object.Hash)
	if !mustHashBoolValue(t, openHash, "bounded") {
		t.Errorf("the volume opened unbounded from a partition hash that carries a length: a read past "+
			"this partition's end would report the next partition's bytes as this volume's (offset %d, length %d)",
			mustHashIntValue(t, openHash, "volume_offset"), mustHashIntValue(t, openHash, "volume_length"))
	}
	handle := mustHashStringValue(t, openHash, "handle")
	t.Cleanup(func() { FatClose(stringObj(handle)) })

	// The label and the length are checked before the tree, so that a selector
	// that found the wrong partition fails saying so rather than reporting
	// three thousand missing files.
	metaPayload, errObj := unwrapPair(t, FatMetadata(stringObj(handle), stringObj("/")))
	if errObj != nil {
		t.Fatalf("fat_metadata(/): %s", errObj.Inspect())
	}
	meta := metaPayload.(*object.Hash)
	if got := mustHashStringValue(t, meta, "volume_label"); got != oracle.Label {
		t.Fatalf("the volume opened from slot %d is labelled %q and the oracle was recorded from %q",
			wantedSlot, got, oracle.Label)
	}
	if got := mustHashIntValue(t, openHash, "volume_length"); got != oracle.PhysicalSize {
		t.Errorf("the partition is %d bytes long and the independent reader measured the volume at %d",
			got, oracle.PhysicalSize)
	}
	if got := mustHashIntValue(t, meta, "cluster_size"); got != oracle.ClusterSize {
		t.Errorf("mutant says the cluster is %d bytes, the independent reader says %d", got, oracle.ClusterSize)
	}

	dirs, files := fatLiveTree(t, handle)
	comparePathSets(t, "directories", dirs, oracle.Dirs)

	oraclePaths := make([]string, 0, len(oracle.Files))
	for _, want := range oracle.Files {
		oraclePaths = append(oraclePaths, want.Path)
	}
	gotPaths := make([]string, 0, len(files))
	for path := range files {
		gotPaths = append(gotPaths, path)
	}
	sort.Strings(gotPaths)
	comparePathSets(t, "files", gotPaths, oraclePaths)

	hashedFiles, skippedDigests := 0, 0
	var hashedBytes int64
	for _, want := range oracle.Files {
		got, ok := files[want.Path]
		if !ok {
			continue // already reported by comparePathSets
		}
		if got.size != want.Size {
			t.Errorf("%s: mutant says %d bytes, the independent reader says %d", want.Path, got.size, want.Size)
		}
		if want.SHA256 == "-" {
			skippedDigests++
			continue
		}
		digest, size, located, truncated := fatHashOf(t, handle, want.Path)
		if digest != want.SHA256 {
			t.Errorf("%s: mutant's content hashes to %s, the independent reader's to %s",
				want.Path, digest, want.SHA256)
			continue
		}
		// This volume is a bounded partition, so a file whose bytes cannot
		// all be located is the signature of a volume whose end was computed
		// from the wrong length -- the failure this whole test exists for.
		if located != size || truncated {
			t.Errorf("%s: the content matched but the report around it does not: size %d, located %d, truncated %v",
				want.Path, size, located, truncated)
		}
		hashedFiles++
		hashedBytes += size
	}
	t.Logf("slot %d: %d directories, %d files, %d content digests over %d bytes, %d digests the oracle does not carry",
		wantedSlot, len(oracle.Dirs), len(oracle.Files), hashedFiles, hashedBytes, skippedDigests)
}

// TestADeletedFATFileComesBackByteForByte is the one test in this package that
// can say whether a recovery recovered the right bytes.
//
// deleted.tsv records what each deletion removed -- path, size and the sha256
// of the content that was there. Nothing readable from the volume can supply
// that, because the deletion is what destroyed it.
//
// The match is made on size and content, never on path. FAT overwrites the
// first character of a deleted entry's short name, and where the long-name
// slots went with it there is nothing to recover the real name from: mutant
// reports _ONE-S~1.BIN for a file written as gone-short.bin and says
// name_source is reconstructed, which is correct and honest. A test that
// matched on path would be asserting that a filesystem does not do what FAT
// does.
func TestADeletedFATFileComesBackByteForByte(t *testing.T) {
	truthPath, ok := corpusFile(t, "fat_synth/deleted.tsv")
	if !ok {
		t.Skip("deleted.tsv is not in this copy of the corpus, and it is the only record of what the deletions removed")
	}

	recovered := 0
	for _, image := range []string{"fat12_deleted.img", "fat16_deleted.img", "fat32_deleted.img"} {
		t.Run(image, func(t *testing.T) {
			imagePath, ok := corpusFile(t, "fat_synth/"+image)
			if !ok {
				return
			}
			truth := readFATDeletedTruth(t, truthPath, image)
			if len(truth) == 0 {
				t.Fatalf("deleted.tsv records nothing for %s, so this subtest asserts nothing", image)
			}
			before := recovered

			handle := openCorpusFAT(t, imagePath)

			// The scan is what enumerates the entries a recovery can name, and
			// a recovery before it is refused -- deliberately, and the refusal
			// says so.
			scanPayload, errObj := unwrapPair(t, FatDeleted(stringObj(handle)))
			if errObj != nil {
				t.Fatalf("fat_deleted: %s", errObj.Inspect())
			}
			scan, ok := scanPayload.(*object.Hash)
			if !ok {
				t.Fatalf("fat_deleted payload is not HASH. got=%T", scanPayload)
			}
			entries := mustHashArrayValue(t, scan, "entries")
			if len(entries) != len(truth) {
				t.Errorf("mutant found %d deleted entries, %d were deleted", len(entries), len(truth))
			}

			// Sizes in this corpus are distinct per image, which is what makes
			// a size the identifier here; a duplicate would make the match
			// ambiguous, so it is refused rather than guessed at.
			bySize := map[int64]*object.Hash{}
			for _, element := range entries {
				entry, ok := element.(*object.Hash)
				if !ok {
					t.Fatalf("a deleted entry is not HASH. got=%T", element)
				}
				size := mustHashIntValue(t, entry, "size")
				if _, clash := bySize[size]; clash {
					t.Fatalf("two deleted entries both record %d bytes, so size cannot identify them here", size)
				}
				bySize[size] = entry
			}

			for _, want := range truth {
				entry, ok := bySize[want.Size]
				if !ok {
					t.Errorf("nothing mutant found records %d bytes, the size of the deleted %s",
						want.Size, want.Path)
					continue
				}
				index := mustHashIntValue(t, entry, "index")

				// The chain is freed by the deletion, so the entry itself
				// locates one cluster and no more. The plain recovery must
				// report exactly that rather than padding to the recorded
				// size, and the assuming variant is the one that can reach the
				// whole file.
				dest := filepath.Join(t.TempDir(), "plain.bin")
				plain, errObj := unwrapPair(t, FatRecoverFile(stringObj(handle), intObj(index), stringObj(dest)))
				if errObj == nil {
					result := plain.(*object.Hash)
					written := mustHashIntValue(t, result, "bytes_written")
					if written > want.Size {
						t.Errorf("%s: the plain recovery wrote %d bytes for a file of %d",
							want.Path, written, want.Size)
					}
					if matched := mustHashBoolValue(t, result, "size_matched"); matched != (written == want.Size) {
						t.Errorf("%s: the plain recovery wrote %d of %d bytes and reports size_matched=%v",
							want.Path, written, want.Size, matched)
					}
				}

				assumedDest := filepath.Join(t.TempDir(), "assumed.bin")
				payload, errObj := unwrapPair(t,
					FatRecoverFileAssumingContiguous(stringObj(handle), intObj(index), stringObj(assumedDest)))
				if errObj != nil {
					t.Errorf("%s: recovering %d bytes assuming contiguity: %s", want.Path, want.Size, errObj.Inspect())
					continue
				}
				result := payload.(*object.Hash)

				if got := mustHashIntValue(t, result, "bytes_written"); got != want.Size {
					t.Errorf("%s: %d bytes recovered, %d were deleted", want.Path, got, want.Size)
				}
				if got := mustHashStringValue(t, result, "digest"); got != want.SHA256 {
					t.Errorf("%s: the recovered bytes hash to %s, the bytes that were deleted hashed to %s",
						want.Path, got, want.SHA256)
					continue
				}
				recovered++

				// The content was right. The report around it must say on what
				// terms, because an examiner acts on that: these bytes are a
				// hypothesis from their position, not a chain read off the
				// volume, and a recovery that returned the right bytes while
				// calling them read-from-the-filesystem would be the more
				// dangerous failure of the two.
				if !mustHashBoolValue(t, result, "assumed") {
					t.Errorf("%s: recovered under an assumption of contiguity and does not report assumed", want.Path)
				}
				if state := mustHashStringValue(t, result, "content_state"); state != "assumed_contiguous" {
					t.Errorf("%s: content_state is %q, want assumed_contiguous", want.Path, state)
				}
				if source := mustHashStringValue(t, result, "name_source"); source != "reconstructed" {
					t.Logf("%s: name_source is %q, so this entry kept a real name through the deletion",
						want.Path, source)
				}
			}
			t.Logf("%d of %d deleted files recovered byte for byte, against the sha256 deleted.tsv recorded",
				recovered-before, len(truth))
		})
	}
	if *corpusDir != "" {
		t.Logf("%d deleted files recovered byte for byte across the deletion volumes", recovered)
	}
	if *corpusDir != "" && recovered == 0 {
		t.Errorf("-corpus.dir is %q and not one deleted file was recovered and checked", *corpusDir)
	}
}

// TestTheVolumeWithNoPrimaryBootSectorIsStillRead covers the one volume in the
// corpus that has no oracle, and records why it has none.
//
// 7-Zip refuses fat32_nobootsec.img outright -- "cannot open the file as
// archive" -- while libfat finds the backup boot sector at sector 6 and reads
// the whole tree. There is therefore nothing to compare against, and the
// comparison is skipped rather than quietly dropped: what is asserted instead
// is the capability itself, that the volume opens and reads, plus the
// self-consistency the volume can be held to on its own.
func TestTheVolumeWithNoPrimaryBootSectorIsStillRead(t *testing.T) {
	image, ok := corpusFile(t, "fat_synth/fat32_nobootsec.img")
	if !ok {
		t.Skip("the volume with no primary boot sector is not in this copy of the corpus")
	}

	handle := openCorpusFAT(t, image)
	payload, errObj := unwrapPair(t, FatMetadata(stringObj(handle), stringObj("/")))
	if errObj != nil {
		t.Fatalf("fat_metadata(/) on a volume whose primary boot sector is destroyed: %s", errObj.Inspect())
	}
	meta := payload.(*object.Hash)
	if got := mustHashStringValue(t, meta, "filesystem"); got != "FAT32" {
		t.Errorf("mutant calls the volume behind the backup boot sector %q, want FAT32", got)
	}
	if label := mustHashStringValue(t, meta, "volume_label"); label == "" {
		t.Error("no volume label was read through the backup boot sector")
	}

	_, files := fatLiveTree(t, handle)
	if len(files) == 0 {
		t.Fatal("the tree read through the backup boot sector holds no files")
	}
	for path, listed := range files {
		digest, size, located, truncated := fatHashOf(t, handle, path)
		if digest == "" {
			t.Errorf("%s: no digest", path)
		}
		if size != listed.size {
			t.Errorf("%s: the listing says %d bytes and the stream says %d", path, listed.size, size)
		}
		if located != size || truncated {
			t.Errorf("%s: a live file reports size %d, located %d, truncated %v", path, size, located, truncated)
		}
	}
	t.Logf("%d files read through the backup boot sector; no oracle exists because 7-Zip refuses this volume", len(files))
}

// --- helpers ----------------------------------------------------------------

type fatListedFile struct {
	size      int64
	shortName string
}

func openCorpusFAT(t *testing.T, image string) string {
	t.Helper()

	payload, errObj := unwrapPair(t, FatOpen(stringObj(image)))
	if errObj != nil {
		t.Fatalf("fat_open(%s): %s", image, errObj.Inspect())
	}
	openHash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("fat_open payload is not HASH. got=%T", payload)
	}
	handle := mustHashStringValue(t, openHash, "handle")
	t.Cleanup(func() { FatClose(stringObj(handle)) })
	return handle
}

// fatLiveTree walks the whole volume through fat_list_files and returns the
// live entries.
//
// Deleted entries are left out, and that is not a simplification: the listing
// reports them alongside live ones with deleted set, while a 7-Zip listing
// holds only what the filesystem still says is there. They are what
// TestADeletedFATFileComesBackByteForByte is about and they are measured
// against different ground truth.
func fatLiveTree(t *testing.T, handle string) ([]string, map[string]fatListedFile) {
	t.Helper()

	dirs := []string{}
	files := map[string]fatListedFile{}
	queue := []string{"/"}
	// A directory loop would otherwise walk forever; FAT has no hard links to
	// make one legitimately, so a path seen twice is a fault and is reported.
	seen := map[string]bool{"/": true}

	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]

		listed, errObj := unwrapPair(t, FatListFiles(stringObj(handle), stringObj(dir)))
		if errObj != nil {
			t.Fatalf("fat_list_files(%q): %s", dir, errObj.Inspect())
		}
		entries, ok := listed.(*object.Array)
		if !ok {
			t.Fatalf("fat_list_files payload is not ARRAY. got=%T", listed)
		}

		for _, element := range entries.Elements {
			row, ok := element.(*object.Hash)
			if !ok {
				t.Fatalf("a listing entry is not HASH. got=%T", element)
			}
			if mustHashBoolValue(t, row, "deleted") {
				continue
			}
			path := mustHashStringValue(t, row, "path")
			if path == "" {
				t.Errorf("an entry of %q has no path", dir)
				continue
			}
			if mustHashBoolValue(t, row, "is_dir") {
				if seen[path] {
					t.Errorf("the walk reached %q twice, so the directory tree holds a loop", path)
					continue
				}
				seen[path] = true
				dirs = append(dirs, path)
				queue = append(queue, path)
				continue
			}
			if _, clash := files[path]; clash {
				t.Errorf("two live entries share the path %q", path)
			}
			files[path] = fatListedFile{
				size:      mustHashIntValue(t, row, "size"),
				shortName: mustHashStringValue(t, row, "short_name"),
			}
		}
	}

	sort.Strings(dirs)
	return dirs, files
}

// fatHashOf hashes one file through the streaming builtin, which is the path a
// script takes for a file too large to hold in memory, and returns the three
// numbers a caller judges the content by.
func fatHashOf(t *testing.T, handle, path string) (digest string, size, located int64, truncated bool) {
	t.Helper()

	payload, errObj := unwrapPair(t, FatHashFile(stringObj(handle), stringObj(path), stringObj("sha256")))
	if errObj != nil {
		t.Errorf("fat_hash_file(%q): %s", path, errObj.Inspect())
		return "", 0, 0, false
	}
	result, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("fat_hash_file payload is not HASH. got=%T", payload)
	}
	if algorithm := mustHashStringValue(t, result, "algorithm"); algorithm != "sha256" {
		t.Errorf("fat_hash_file(%q) answered for %q, not sha256", path, algorithm)
	}
	return mustHashStringValue(t, result, "digest"),
		mustHashIntValue(t, result, "size"),
		mustHashIntValue(t, result, "located_bytes"),
		mustHashBoolValue(t, result, "truncated")
}
