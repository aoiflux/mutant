package builtin

// Real-image tests for the HFS builtins. See corpus_oracle_test.go for why
// these exist and why the corpus path arrives as a flag.
//
// WHAT THIS SUITE CAN AND CANNOT PROVE, stated plainly because the FAT half of
// it can prove more. The HFS oracle is an hfsutils listing: it carries each
// file's two fork sizes, each directory's child count, the volume's name and
// its free space. It carries NO content digest, so nothing here can say that
// an HFS file's bytes are the right bytes -- only that its size is the size an
// independent implementation read. What stands in for the content check is the
// streaming test at the bottom, which requires a file to locate all of its own
// bytes; that is weaker, and it is weaker on purpose rather than by omission.
//
// Classic HFS only, and the oracle generator says why: hfsutils cannot read
// HFS+ at all, and on a wrapped volume it reads the HFS WRAPPER while libhfs
// reads the embedded HFS+ volume inside it -- two different filesystems with
// different contents. The corpus therefore has no oracle for its HFS+ and HFSX
// volumes, and those are not compared here rather than compared against the
// wrong thing.

import (
	"path/filepath"
	"sort"
	"testing"

	"mutant/object"
)

var hfsCorpusVolumes = []struct {
	rel  string
	what string
}{
	{"hfs_synth/classic_small.dd", "the smallest populated classic volume: one directory and two files"},
	{"hfs_synth/classic_full.dd", "a classic volume with 367 files, non-ASCII MacRoman names, and a directory 361 items wide"},
	{"hfs_synth/classic_frag.dd", "a fragmented extent on classic HFS, where the extents overflow file is reached"},
	{"hfs_synth/hfs_classic.dd", "an empty classic volume: the oracle carries its name and free space and no files at all"},
	{"img11_hfs.dd", "a real 512 MB classic HFS volume, 1721 files"},
}

// TestARealHFSVolumeListsWhatAnIndependentReaderSees walks each populated
// volume and requires mutant's tree and its file sizes to match hfsutils.
//
// Names are the interesting part here in a way they are not on FAT. A classic
// HFS name is MacRoman, the oracle records the raw bytes hfsutils printed, and
// mutant returns UTF-8. The comparison therefore runs through this test's own
// MacRoman table rather than libhfs's, so the decode is measured and not
// assumed -- see decodeMacRoman.
func TestARealHFSVolumeListsWhatAnIndependentReaderSees(t *testing.T) {
	compared := 0
	for _, volume := range hfsCorpusVolumes {
		t.Run(filepath.Base(volume.rel), func(t *testing.T) {
			image, ok := corpusFile(t, volume.rel)
			if !ok {
				return
			}
			oraclePath, ok := corpusFile(t, volume.rel+".oracle.tsv")
			if !ok {
				return
			}
			oracle := readHFSOracle(t, oraclePath)
			if len(oracle.Files) == 0 {
				t.Skipf("the oracle for this volume lists no files, so there is no tree to compare: %s", volume.what)
			}
			compared++
			t.Logf("what only this volume covers: %s", volume.what)

			handle := openCorpusHFS(t, image)
			dirs, files := hfsLiveTree(t, handle)

			wantDirs := make([]string, 0, len(oracle.Dirs))
			for _, dir := range oracle.Dirs {
				wantDirs = append(wantDirs, dir.Path)
			}
			comparePathSets(t, "directories", dirs, wantDirs)

			wantFiles := make([]string, 0, len(oracle.Files))
			for _, file := range oracle.Files {
				wantFiles = append(wantFiles, file.Path)
			}
			gotFiles := make([]string, 0, len(files))
			for path := range files {
				gotFiles = append(gotFiles, path)
			}
			sort.Strings(gotFiles)
			comparePathSets(t, "files", gotFiles, wantFiles)

			nonASCII, forks := 0, 0
			for _, want := range oracle.Files {
				if _, ok := files[want.Path]; !ok {
					continue // already reported by comparePathSets
				}
				if !isASCII(want.Path) {
					nonASCII++
				}
				meta := hfsMetadataOf(t, handle, want.Path)
				if meta == nil {
					continue
				}
				if got := mustHashIntValue(t, meta, "size"); got != want.DataSize {
					t.Errorf("%s: mutant says the data fork is %d bytes, the independent reader says %d",
						want.Path, got, want.DataSize)
				}
				if got := mustHashIntValue(t, meta, "resource_fork_size"); got != want.RsrcSize {
					t.Errorf("%s: mutant says the resource fork is %d bytes, the independent reader says %d",
						want.Path, got, want.RsrcSize)
				}
				if want.RsrcSize != 0 {
					forks++
				}
			}

			t.Logf("%d directories, %d files, %d of them with a non-ASCII MacRoman name",
				len(oracle.Dirs), len(oracle.Files), nonASCII)
			// Said out loud because an assertion that always compares zero to
			// zero is not coverage. Every file in this corpus has an empty
			// resource fork, so the fork comparison above would pass against a
			// parser that returned 0 unconditionally. Filling that gap needs a
			// volume with a real resource fork, which is a corpus change and
			// not a test change.
			if forks == 0 {
				t.Logf("no file on this volume has a resource fork, so the resource-fork comparison " +
					"discriminates nothing here beyond a non-zero being wrong")
			}
		})
	}
	if *corpusDir != "" && compared == 0 {
		t.Errorf("-corpus.dir is %q and not one HFS volume was compared: the suite would have reported "+
			"success while measuring nothing", *corpusDir)
	}
}

// TestARealHFSVolumeAgreesAboutItsFreeSpace compares a derived quantity, which
// is why it is worth its own test.
//
// Free space is two fields multiplied -- free_blocks times block_size -- and
// an allocation block size read from the wrong offset gives a plausible answer
// rather than an obviously broken one. hfsutils computes the same number from
// its own reading of the volume header, so agreement means both read the same
// two fields correctly. This runs on the empty volume too, which is the only
// thing the empty volume can be asked.
func TestARealHFSVolumeAgreesAboutItsFreeSpace(t *testing.T) {
	compared := 0
	for _, volume := range hfsCorpusVolumes {
		t.Run(filepath.Base(volume.rel), func(t *testing.T) {
			image, ok := corpusFile(t, volume.rel)
			if !ok {
				return
			}
			oraclePath, ok := corpusFile(t, volume.rel+".oracle.tsv")
			if !ok {
				return
			}
			compared++

			oracle := readHFSOracle(t, oraclePath)
			handle := openCorpusHFS(t, image)
			meta := hfsMetadataOf(t, handle, "/")
			if meta == nil {
				t.Fatal("hfs_metadata(/) returned nothing")
			}

			if got := mustHashStringValue(t, meta, "name"); got != oracle.VolumeName {
				t.Errorf("mutant names the volume %q, the independent reader names it %q", got, oracle.VolumeName)
			}

			blockSize := mustHashIntValue(t, meta, "block_size")
			freeBlocks := mustHashIntValue(t, meta, "free_blocks")
			if free := freeBlocks * blockSize; free != oracle.FreeBytes {
				t.Errorf("mutant reports %d free blocks of %d bytes, %d free in all, where the "+
					"independent reader measured %d", freeBlocks, blockSize, free, oracle.FreeBytes)
			}

			// A total that does not cover the free blocks it claims would make
			// every number above arithmetic on a misread field.
			if total := mustHashIntValue(t, meta, "total_blocks"); total < freeBlocks {
				t.Errorf("the volume claims %d free blocks out of %d in total", freeBlocks, total)
			}

			// Both numbers, not an assertion of agreement: the comparison above
			// has already reported a mismatch, and a log line claiming they match
			// would contradict it in the same output.
			t.Logf("%q: %d free blocks of %d bytes is %d free; the independent reader measured %d",
				oracle.VolumeName, freeBlocks, blockSize, freeBlocks*blockSize, oracle.FreeBytes)
		})
	}
	if *corpusDir != "" {
		t.Logf("%d volumes' free space compared", compared)
	}
	if *corpusDir != "" && compared == 0 {
		t.Errorf("-corpus.dir is %q and no HFS volume's free space was compared", *corpusDir)
	}
}

// TestARealHFSDirectoryHoldsTheItemsTheOracleCounted checks each directory's
// width against the count hfsutils recorded.
//
// mutant has no child-count field, so the count compared is the number of
// entries hfs_list_files returns. That makes this the one test here that would
// catch a directory whose contents are read short -- a catalogue walk that
// stops early gives a correct-looking listing of everything it did reach, and
// nothing in a path-set comparison distinguishes "this directory holds nine
// items" from "this directory holds nine of its eleven items" unless something
// else counted them. classic_full.dd carries a directory 361 items wide for
// exactly this reason.
func TestARealHFSDirectoryHoldsTheItemsTheOracleCounted(t *testing.T) {
	checked := 0
	for _, volume := range hfsCorpusVolumes {
		t.Run(filepath.Base(volume.rel), func(t *testing.T) {
			image, ok := corpusFile(t, volume.rel)
			if !ok {
				return
			}
			oraclePath, ok := corpusFile(t, volume.rel+".oracle.tsv")
			if !ok {
				return
			}
			oracle := readHFSOracle(t, oraclePath)
			if len(oracle.Dirs) == 0 {
				t.Skipf("the oracle for this volume counts no directories: %s", volume.what)
			}

			handle := openCorpusHFS(t, image)
			widest := int64(0)
			for _, dir := range oracle.Dirs {
				listed, errObj := unwrapPair(t, HFSListFiles(stringObj(handle), stringObj(dir.Path)))
				if errObj != nil {
					t.Errorf("hfs_list_files(%q): %s", dir.Path, errObj.Inspect())
					continue
				}
				entries, ok := listed.(*object.Array)
				if !ok {
					t.Fatalf("hfs_list_files payload is not ARRAY. got=%T", listed)
				}
				if got := int64(len(entries.Elements)); got != dir.Items {
					t.Errorf("%s: mutant lists %d items, the independent reader counted %d",
						dir.Path, got, dir.Items)
				}
				if dir.Items > widest {
					widest = dir.Items
				}
				checked++
			}
			t.Logf("%d directories counted, the widest holding %d items", len(oracle.Dirs), widest)
		})
	}
	if *corpusDir != "" && checked == 0 {
		t.Errorf("-corpus.dir is %q and no HFS directory was counted", *corpusDir)
	}
}

// TestAnHFSFileLocatesAllOfItsOwnBytes is what stands in for the content check
// the HFS oracle cannot provide.
//
// It streams every file through hfs_hash_file and requires the three numbers
// beside the digest to agree with the size an independent reader measured: the
// stream's own size, the bytes it could locate, and the truncated flag. A live
// file's bytes are all locatable, so a shortfall here means the extents could
// not be followed to the end of a file the catalogue describes -- which on the
// fragmented volume means the extents overflow file was not reached.
func TestAnHFSFileLocatesAllOfItsOwnBytes(t *testing.T) {
	hashed := 0
	for _, volume := range hfsCorpusVolumes {
		t.Run(filepath.Base(volume.rel), func(t *testing.T) {
			image, ok := corpusFile(t, volume.rel)
			if !ok {
				return
			}
			oraclePath, ok := corpusFile(t, volume.rel+".oracle.tsv")
			if !ok {
				return
			}
			oracle := readHFSOracle(t, oraclePath)
			if len(oracle.Files) == 0 {
				t.Skipf("the oracle for this volume lists no files: %s", volume.what)
			}

			handle := openCorpusHFS(t, image)
			var bytesHashed int64
			empty := 0
			for _, want := range oracle.Files {
				payload, errObj := unwrapPair(t,
					HFSHashFile(stringObj(handle), stringObj(want.Path), stringObj("sha256")))
				if errObj != nil {
					t.Errorf("hfs_hash_file(%q), a file of %d bytes: %s", want.Path, want.DataSize, errObj.Inspect())
					continue
				}
				result, ok := payload.(*object.Hash)
				if !ok {
					t.Fatalf("hfs_hash_file payload is not HASH. got=%T", payload)
				}
				size := mustHashIntValue(t, result, "size")
				located := mustHashIntValue(t, result, "located_bytes")
				truncated := mustHashBoolValue(t, result, "truncated")
				if size != want.DataSize {
					t.Errorf("%s: the stream says %d bytes, the independent reader says %d",
						want.Path, size, want.DataSize)
				}
				if located != size || truncated {
					t.Errorf("%s: a live file of %d bytes located %d with truncated=%v",
						want.Path, size, located, truncated)
				}
				if digest := mustHashStringValue(t, result, "digest"); digest == "" {
					t.Errorf("%s: no digest", want.Path)
				}
				if want.DataSize == 0 {
					empty++
				}
				bytesHashed += size
				hashed++
			}
			t.Logf("%d files streamed over %d bytes, %d of them empty", len(oracle.Files), bytesHashed, empty)
		})
	}
	if *corpusDir != "" && hashed == 0 {
		t.Errorf("-corpus.dir is %q and no HFS file was streamed", *corpusDir)
	}
}

// --- helpers ----------------------------------------------------------------

func openCorpusHFS(t *testing.T, image string) string {
	t.Helper()

	payload, errObj := unwrapPair(t, HFSOpen(stringObj(image)))
	if errObj != nil {
		t.Fatalf("hfs_open(%s): %s", image, errObj.Inspect())
	}
	openHash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("hfs_open payload is not HASH. got=%T", payload)
	}
	handle := mustHashStringValue(t, openHash, "handle")
	t.Cleanup(func() { HFSClose(stringObj(handle)) })
	return handle
}

// hfsLiveTree walks the whole volume through hfs_list_files.
//
// System entries are kept rather than filtered: the oracle is generated with
// hls -a, which shows them too, so dropping them here would hide a
// disagreement about what is on the volume.
func hfsLiveTree(t *testing.T, handle string) ([]string, map[string]bool) {
	t.Helper()

	dirs := []string{}
	files := map[string]bool{}
	queue := []string{"/"}
	seen := map[string]bool{"/": true}

	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]

		listed, errObj := unwrapPair(t, HFSListFiles(stringObj(handle), stringObj(dir)))
		if errObj != nil {
			t.Fatalf("hfs_list_files(%q): %s", dir, errObj.Inspect())
		}
		entries, ok := listed.(*object.Array)
		if !ok {
			t.Fatalf("hfs_list_files payload is not ARRAY. got=%T", listed)
		}

		for _, element := range entries.Elements {
			row, ok := element.(*object.Hash)
			if !ok {
				t.Fatalf("a listing entry is not HASH. got=%T", element)
			}
			path := mustHashStringValue(t, row, "path")
			if path == "" {
				t.Errorf("an entry of %q has no path", dir)
				continue
			}
			if mustHashBoolValue(t, row, "is_dir") {
				if seen[path] {
					t.Errorf("the walk reached %q twice, so the catalogue holds a loop", path)
					continue
				}
				seen[path] = true
				dirs = append(dirs, path)
				queue = append(queue, path)
				continue
			}
			if files[path] {
				t.Errorf("two entries share the path %q", path)
			}
			files[path] = true
		}
	}

	sort.Strings(dirs)
	return dirs, files
}

func hfsMetadataOf(t *testing.T, handle, path string) *object.Hash {
	t.Helper()

	payload, errObj := unwrapPair(t, HFSMetadata(stringObj(handle), stringObj(path)))
	if errObj != nil {
		t.Errorf("hfs_metadata(%q): %s", path, errObj.Inspect())
		return nil
	}
	meta, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("hfs_metadata payload is not HASH. got=%T", payload)
	}
	return meta
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
