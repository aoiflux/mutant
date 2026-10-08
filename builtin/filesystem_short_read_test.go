package builtin

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	libfat "github.com/aoiflux/libfat"

	"mutant/object"
)

// fatStreamFileStart is where writeFATFileEntry's file begins in the image
// buildFAT16Image makes: one reserved sector, two FATs, the root directory,
// and cluster 2 (the subdirectory) ahead of the file's first cluster, 3.
const fatStreamFileStart = fatTestSectorSize + 2*fatTestFATSectors*fatTestSectorSize +
	fatTestRootDirSector*fatTestSectorSize + fatTestSectorSize

// TestAnImageThatEndsInsideAFileFailsEveryRead is M26-FS1-003's regression
// test. The file's clusters are all on the chain, so located_bytes is its whole
// size; the image -- or the partition it was opened as -- ends partway through
// them. libfat answers the read with what it had and io.EOF, which io.Copy and
// the windowed read took for the end of the file: the extraction wrote a prefix
// under the file's name with truncated false, the hash was a prefix's, and a
// window past the cut came back empty with no error.
func TestAnImageThatEndsInsideAFileFailsEveryRead(t *testing.T) {
	content := rampBytes(65536)
	image := buildFAT16Image(t, 2, 0)
	writeFATFileEntry(t, image, 2, "EVIDENCEBIN", content)
	if !bytes.Equal(image[fatStreamFileStart:fatStreamFileStart+len(content)], content) {
		t.Fatalf("the fixture's file does not start at byte %d", fatStreamFileStart)
	}

	const cut = 70000
	readable := int64(cut - fatStreamFileStart)
	dir := t.TempDir()
	short := filepath.Join(dir, "short.img")
	whole := filepath.Join(dir, "whole.img")
	if err := os.WriteFile(short, image[:cut], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(whole, image, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		args []object.Object
	}{
		{"an image cut short", []object.Object{stringObj(short)}},
		{"a partition shorter than its volume", []object.Object{stringObj(whole), intObj(0), intObj(cut)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, errObj := unwrapPair(t, FatOpen(tc.args...))
			if errObj != nil {
				t.Fatalf("fat_open: %s", errObj.Inspect())
			}
			handle := mustHashValue(t, payload.(*object.Hash), "handle")
			t.Cleanup(func() { FatClose(handle) })
			path := stringObj(onlyFileInRoot(t, handle))

			dest := filepath.Join(t.TempDir(), "out.bin")
			_, errObj = unwrapPairNoFatal(FatExtractFile(handle, path, stringObj(dest)))
			if errObj == nil {
				t.Errorf("fat_extract_file reported success for a file the image ends inside")
			} else {
				for _, want := range []string{"could not be read", "was removed"} {
					if !strings.Contains(errObj.Message, want) {
						t.Errorf("the extraction's refusal does not say %q: %s", want, errObj.Message)
					}
				}
			}
			if _, err := os.Stat(dest); !os.IsNotExist(err) {
				t.Errorf("a prefix was left at %s under the file's name", dest)
			}

			if _, errObj = unwrapPairNoFatal(FatHashFile(handle, path, stringObj("sha256"))); errObj == nil {
				t.Errorf("fat_hash_file reported a digest for a file the image ends inside")
			}

			// Inside the part the image holds, a window is the bytes there --
			// including one that ends exactly where the image does.
			for _, w := range [][2]int64{{0, 4096}, {readable - 512, 512}} {
				got, errObj := unwrapPair(t, FatReadFileAt(handle, path, intObj(w[0]), intObj(w[1])))
				if errObj != nil {
					t.Fatalf("fat_read_file_at(%d, %d) inside the image: %s", w[0], w[1], errObj.Inspect())
				}
				if !bytes.Equal(got.(*object.Bytes).Value, content[w[0]:w[0]+w[1]]) {
					t.Errorf("fat_read_file_at(%d, %d) is not the bytes at that offset", w[0], w[1])
				}
			}
			// One that crosses the end, or starts past it, is refused rather
			// than handed back short or empty.
			for _, w := range [][2]int64{{readable - 100, 200}, {40000, 4096}} {
				got, errObj := unwrapPairNoFatal(FatReadFileAt(handle, path, intObj(w[0]), intObj(w[1])))
				if errObj == nil {
					t.Errorf("fat_read_file_at(%d, %d) returned %d bytes and no error past the end of the image",
						w[0], w[1], len(got.(*object.Bytes).Value))
				}
			}
		})
	}
}

// TestARecoveryCountsWhatLiesPastTheImageAsUnlocated is M26-FS2-005's
// regression test. GONE.TXT's surviving run is its first cluster, and the
// image ends halfway through it. fsRunReader zero-filled the half the image
// does not hold, swallowed io.EOF, and recoveryFromRuns counted the whole run
// as located -- zeros labelled as bytes read from the image.
func TestARecoveryCountsWhatLiesPastTheImageAsUnlocated(t *testing.T) {
	image := buildFAT16RecoverableImage(t)
	half := int64(fatTestSectorSize / 2)
	cut := int64(fatRecoverClusterOffset(3)) + half
	truncated := image[:cut]

	volume, err := libfat.OpenWithOptions(bytes.NewReader(truncated), libfat.OpenOptions{})
	if err != nil {
		t.Fatalf("libfat refused the truncated image: %v", err)
	}
	session := &realFATSession{reader: bytes.NewReader(truncated), volume: volume}
	scan, err := session.ScanDeleted()
	if err != nil {
		t.Fatalf("ScanDeleted: %v", err)
	}
	recovery, err := session.RecoverDeleted(indexOfScannedEntry(t, scan, "ONE.TXT"), false)
	if err != nil {
		t.Fatalf("RecoverDeleted: %v", err)
	}

	if recovery.Length != fatTestSectorSize {
		t.Fatalf("the recovery is %d bytes, want the run's %d", recovery.Length, fatTestSectorSize)
	}
	if recovery.LocatedBytes != half {
		t.Errorf("located_bytes = %d, want the %d the image holds", recovery.LocatedBytes, half)
	}
	if recovery.UnlocatedBytes != half {
		t.Errorf("unlocated_bytes = %d, want the %d past the end of the image", recovery.UnlocatedBytes, half)
	}

	written := mustReadRecovery(t, recovery)
	if !bytes.Equal(written[:half], bytes.Repeat([]byte{'A'}, int(half))) {
		t.Errorf("the half the image holds is not cluster 3's bytes")
	}
	if !bytes.Equal(written[half:], make([]byte, half)) {
		t.Errorf("the half past the image is not zeros")
	}

	caveats := strings.Join(recoveryCaveats(recovery, recovery.Length), "\n")
	if !strings.Contains(caveats, "past the end of the image") || !strings.Contains(caveats, fmt.Sprintf("byte %d", cut)) {
		t.Errorf("no caveat names the end of the image:\n%s", caveats)
	}
	if strings.Contains(caveats, "could not place") {
		t.Errorf("bytes the volume placed are described as bytes it could not place:\n%s", caveats)
	}
}

// When the image ends before a run's first byte nothing at all was located,
// and a file of zeros under a deleted file's name is refused, as an empty one
// already was.
func TestARecoveryWhollyPastTheImageIsRefused(t *testing.T) {
	image := buildFAT16RecoverableImage(t)
	path := filepath.Join(t.TempDir(), "short.img")
	if err := os.WriteFile(path, image[:fatRecoverClusterOffset(3)], 0o600); err != nil {
		t.Fatal(err)
	}

	payload, errObj := unwrapPair(t, FatOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("fat_open: %s", errObj.Inspect())
	}
	handle := mustHashValue(t, payload.(*object.Hash), "handle")
	t.Cleanup(func() { FatClose(handle) })

	scanned, errObj := unwrapPair(t, FatDeleted(handle))
	if errObj != nil {
		t.Fatalf("fat_deleted: %s", errObj.Inspect())
	}
	index := int64(-1)
	for _, e := range hashValueByKey(scanned.(*object.Hash), "entries").(*object.Array).Elements {
		row := e.(*object.Hash)
		if strings.HasSuffix(strings.ToUpper(mustHashStringValue(t, row, "name")), "ONE.TXT") {
			index = mustHashIntValue(t, row, "index")
		}
	}
	if index < 0 {
		t.Fatalf("fat_deleted did not report GONE.TXT")
	}

	dest := filepath.Join(t.TempDir(), "gone.txt")
	_, errObj = unwrapPairNoFatal(FatRecoverFile(handle, intObj(index), stringObj(dest)))
	if errObj == nil {
		t.Errorf("a recovery none of whose bytes the image holds wrote a file")
	} else if !strings.Contains(errObj.Message, "past its end") {
		t.Errorf("the refusal does not say where the bytes went: %s", errObj.Message)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Errorf("a file of zeros was left at %s", dest)
	}
}

// fs_hash names the digest after the algorithm that made it (M26-FS1-017's
// sibling outside the image families): "" and "SHA1" are not labels.
func TestFsHashReportsTheAlgorithmThatMadeTheDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.bin")
	if err := os.WriteFile(path, rampBytes(1000), 0o600); err != nil {
		t.Fatal(err)
	}
	for asked, want := range map[string]string{"": "sha256", "SHA256": "sha256", "SHA1": "sha1", " md5 ": "md5"} {
		payload, errObj := unwrapPair(t, FsHash(stringObj(path), stringObj(asked)))
		if errObj != nil {
			t.Fatalf("fs_hash(%q): %s", asked, errObj.Inspect())
		}
		if got := mustHashStringValue(t, payload.(*object.Hash), "algo"); got != want {
			t.Errorf("fs_hash(%q) reported algo %q, want %q", asked, got, want)
		}
	}
}
