package builtin

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// streamFamily is one of the six filesystem families reduced to what the
// streaming work is about: the three builtins a script calls, and a way to get
// a handle over a session holding known bytes.
type streamFamily struct {
	name    string
	extract func(...object.Object) object.Object
	hash    func(...object.Object) object.Object
	readAt  func(...object.Object) object.Object
	handle  func(t *testing.T, files map[string][]byte, located map[string]int64) object.Object
}

func streamFamilies() []streamFamily {
	return []streamFamily{
		{"ntfs", NtfsExtractFile, NtfsHashFile, NtfsReadFileAt,
			func(t *testing.T, files map[string][]byte, located map[string]int64) object.Object {
				installFakeNTFSBackend(t, &fakeNTFSBackend{session: &fakeNTFSSession{files: files, located: located}})
				return streamHandle(t, NtfsOpen)
			}},
		{"fat", FatExtractFile, FatHashFile, FatReadFileAt,
			func(t *testing.T, files map[string][]byte, located map[string]int64) object.Object {
				installFakeFATBackend(t, &fakeFATBackend{session: &fakeFATSession{files: files, located: located}})
				return streamHandle(t, FatOpen)
			}},
		{"xfat", XFATExtractFile, XFATHashFile, XFATReadFileAt,
			func(t *testing.T, files map[string][]byte, located map[string]int64) object.Object {
				installFakeXFATBackend(t, &fakeXFATBackend{session: &fakeXFATSession{files: files, located: located}})
				return streamHandle(t, XFATOpen)
			}},
		{"ext", ExtExtractFile, ExtHashFile, ExtReadFileAt,
			func(t *testing.T, files map[string][]byte, located map[string]int64) object.Object {
				installFakeEXTBackend(t, &fakeEXTBackend{session: &fakeEXTSession{files: files, located: located}})
				return streamHandle(t, ExtOpen)
			}},
		{"hfs", HFSExtractFile, HFSHashFile, HFSReadFileAt,
			func(t *testing.T, files map[string][]byte, located map[string]int64) object.Object {
				installFakeHFSBackend(t, &fakeHFSBackend{session: &fakeHFSSession{files: files, located: located}})
				return streamHandle(t, HFSOpen)
			}},
		{"xfs", XFSExtractFile, XFSHashFile, XFSReadFileAt,
			func(t *testing.T, files map[string][]byte, located map[string]int64) object.Object {
				installFakeXFSBackend(t, &fakeXFSBackend{session: &fakeXFSSession{files: files, located: located}})
				return streamHandle(t, XFSOpen)
			}},
	}
}

func streamHandle(t *testing.T, open func(...object.Object) object.Object) object.Object {
	t.Helper()

	payload, errObj := unwrapPair(t, open(stringObj("synthetic.img")))
	if errObj != nil {
		t.Fatalf("opening the fake volume: %s", errObj.Inspect())
	}
	return mustHashValue(t, payload.(*object.Hash), "handle")
}

// rampBytes is content whose every byte says where it came from, so a stream
// that lands the right number of bytes in the wrong order still fails.
func rampBytes(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte((i*7 + 13) % 251)
	}
	return data
}

// A file of more than one chunk, so the copy loop is exercised rather than
// short-circuited, and not a whole number of them, so an off-by-one in the
// last chunk has somewhere to show.
const streamTestSize = fsStreamChunkBytes*2 + 4097

func TestExtractionWritesTheWholeFileAndItsDigest(t *testing.T) {
	content := rampBytes(streamTestSize)

	for _, fam := range streamFamilies() {
		t.Run(fam.name, func(t *testing.T) {
			handle := fam.handle(t, map[string][]byte{"/case/evidence.bin": content}, nil)
			dest := filepath.Join(t.TempDir(), "extracted.bin")

			payload, errObj := unwrapPair(t, fam.extract(handle, stringObj("/case/evidence.bin"), stringObj(dest)))
			if errObj != nil {
				t.Fatalf("%s_extract_file: %s", fam.name, errObj.Inspect())
			}
			result := payload.(*object.Hash)

			written, err := os.ReadFile(dest)
			if err != nil {
				t.Fatalf("reading the extraction: %v", err)
			}
			if !bytes.Equal(written, content) {
				t.Fatalf("the extracted file is not the file: %d bytes written, %d expected",
					len(written), len(content))
			}
			if got := mustHashIntValue(t, result, "bytes_written"); got != int64(len(content)) {
				t.Fatalf("reported bytes_written %d, want %d", got, len(content))
			}
			if got := mustHashIntValue(t, result, "size"); got != int64(len(content)) {
				t.Fatalf("reported size %d, want %d", got, len(content))
			}
			if got := mustHashIntValue(t, result, "located_bytes"); got != int64(len(content)) {
				t.Fatalf("reported located_bytes %d, want %d", got, len(content))
			}
			if mustHashBoolValue(t, result, "truncated") {
				t.Fatalf("an intact file was reported as truncated")
			}
			if got := mustHashStringValue(t, result, "digest"); got != sha256Hex(content) {
				t.Fatalf("digest %s does not cover what was written", got)
			}
			if got := mustHashStringValue(t, result, "algorithm"); got != "sha256" {
				t.Fatalf("reported algorithm %q, want sha256", got)
			}
			if got := mustHashStringValue(t, result, "dest"); got != dest {
				t.Fatalf("reported dest %q, want %q", got, dest)
			}
		})
	}
}

// Two files in one image can carry the same name, and evidence written over by
// accident does not come back.
func TestExtractionWillNotWriteOverAnExistingFile(t *testing.T) {
	existing := []byte("the first extraction")

	for _, fam := range streamFamilies() {
		t.Run(fam.name, func(t *testing.T) {
			handle := fam.handle(t, map[string][]byte{"/a.bin": rampBytes(64)}, nil)
			dest := filepath.Join(t.TempDir(), "extracted.bin")
			if err := os.WriteFile(dest, existing, 0o600); err != nil {
				t.Fatalf("seeding the destination: %v", err)
			}

			_, errObj := unwrapPairNoFatal(fam.extract(handle, stringObj("/a.bin"), stringObj(dest)))
			if errObj == nil {
				t.Fatalf("%s_extract_file wrote over an existing file", fam.name)
			}

			after, err := os.ReadFile(dest)
			if err != nil {
				t.Fatalf("reading the destination back: %v", err)
			}
			if !bytes.Equal(after, existing) {
				t.Fatalf("the existing file was modified: %q", after)
			}
		})
	}
}

// The forensically interesting case: a deleted entry whose chain was broken.
// The entry still records the original length and only a prefix of it leads
// anywhere, so what follows on the volume belongs to something else.
func TestATruncatedChainExtractsItsPrefixAndSaysSo(t *testing.T) {
	content := rampBytes(8192)
	const locatedBytes = int64(3000)

	for _, fam := range streamFamilies() {
		t.Run(fam.name, func(t *testing.T) {
			handle := fam.handle(t,
				map[string][]byte{"/deleted.bin": content},
				map[string]int64{"/deleted.bin": locatedBytes})
			dest := filepath.Join(t.TempDir(), "recovered.bin")

			payload, errObj := unwrapPair(t, fam.extract(handle, stringObj("/deleted.bin"), stringObj(dest)))
			if errObj != nil {
				t.Fatalf("%s_extract_file: %s", fam.name, errObj.Inspect())
			}
			result := payload.(*object.Hash)

			if !mustHashBoolValue(t, result, "truncated") {
				t.Fatalf("a chain that reached %d of %d bytes was not reported as truncated",
					locatedBytes, len(content))
			}
			if got := mustHashIntValue(t, result, "bytes_written"); got != locatedBytes {
				t.Fatalf("wrote %d bytes, want the %d that were located", got, locatedBytes)
			}
			if got := mustHashIntValue(t, result, "size"); got != int64(len(content)) {
				t.Fatalf("reported size %d, want the recorded %d", got, len(content))
			}

			written, err := os.ReadFile(dest)
			if err != nil {
				t.Fatalf("reading the extraction: %v", err)
			}
			if !bytes.Equal(written, content[:locatedBytes]) {
				t.Fatalf("the recovered prefix is not the prefix")
			}

			// The digest is of what was written. A digest of the whole
			// recorded length would be a digest of bytes nobody recovered.
			if got := mustHashStringValue(t, result, "digest"); got != sha256Hex(content[:locatedBytes]) {
				t.Fatalf("digest %s does not cover the prefix that was written", got)
			}
		})
	}
}

func TestHashingReadsAFileWithoutWritingOneAnywhere(t *testing.T) {
	content := rampBytes(streamTestSize)

	for _, fam := range streamFamilies() {
		t.Run(fam.name, func(t *testing.T) {
			handle := fam.handle(t, map[string][]byte{"/evidence.bin": content}, nil)
			dir := t.TempDir()
			t.Chdir(dir)

			payload, errObj := unwrapPair(t, fam.hash(handle, stringObj("/evidence.bin"), stringObj("sha256")))
			if errObj != nil {
				t.Fatalf("%s_hash_file: %s", fam.name, errObj.Inspect())
			}
			result := payload.(*object.Hash)

			if got := mustHashStringValue(t, result, "digest"); got != sha256Hex(content) {
				t.Fatalf("digest %s is not the file's sha256", got)
			}
			if got := mustHashIntValue(t, result, "bytes_hashed"); got != int64(len(content)) {
				t.Fatalf("hashed %d bytes, want %d", got, len(content))
			}
			if mustHashBoolValue(t, result, "truncated") {
				t.Fatalf("an intact file was reported as truncated")
			}

			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("listing the working directory: %v", err)
			}
			if len(entries) != 0 {
				t.Fatalf("hashing left %d file(s) behind", len(entries))
			}
		})
	}
}

func TestEveryAlgorithmTheLanguageAcceptsIsTheAlgorithmItComputes(t *testing.T) {
	content := rampBytes(4096)

	md5Sum := md5.Sum(content)
	sha1Sum := sha1.Sum(content)

	cases := []struct {
		algorithm string
		want      string
	}{
		{"md5", hex.EncodeToString(md5Sum[:])},
		{"sha1", hex.EncodeToString(sha1Sum[:])},
		{"sha256", sha256Hex(content)},
		// case_open's custody policy treats an unstated algorithm as sha256,
		// and one table serves both.
		{"", sha256Hex(content)},
	}

	for _, tc := range cases {
		t.Run("algorithm="+tc.algorithm, func(t *testing.T) {
			fam := streamFamilies()[0]
			handle := fam.handle(t, map[string][]byte{"/a.bin": content}, nil)

			payload, errObj := unwrapPair(t, fam.hash(handle, stringObj("/a.bin"), stringObj(tc.algorithm)))
			if errObj != nil {
				t.Fatalf("hashing with %q: %s", tc.algorithm, errObj.Inspect())
			}
			result := payload.(*object.Hash)

			if got := mustHashStringValue(t, result, "digest"); got != tc.want {
				t.Fatalf("digest for %q is %s, want %s", tc.algorithm, got, tc.want)
			}
			if got := mustHashStringValue(t, result, "algorithm"); got != tc.algorithm {
				t.Fatalf("reported algorithm %q, want %q", got, tc.algorithm)
			}
		})
	}
}

func TestAnUnknownAlgorithmIsRefusedByTheNameThatWasAsked(t *testing.T) {
	fam := streamFamilies()[0]
	handle := fam.handle(t, map[string][]byte{"/a.bin": rampBytes(16)}, nil)

	_, errObj := unwrapPairNoFatal(fam.hash(handle, stringObj("/a.bin"), stringObj("sha3")))
	if errObj == nil {
		t.Fatalf("an unknown algorithm was accepted")
	}
	if !strings.Contains(errObj.Message, "sha3") {
		t.Fatalf("the refusal does not name the algorithm: %s", errObj.Message)
	}
	if !strings.Contains(errObj.Message, BuiltinNameNtfsHashFile) {
		t.Fatalf("the refusal names the wrong builtin: %s", errObj.Message)
	}
}

// A digest over a recovered prefix will not match a hash set entry for the
// intact file. That is the honest answer, and `truncated` is what makes it
// legible rather than puzzling.
func TestHashingATruncatedChainCoversOnlyWhatWasFound(t *testing.T) {
	content := rampBytes(9000)
	const locatedBytes = int64(1024)

	fam := streamFamilies()[0]
	handle := fam.handle(t,
		map[string][]byte{"/deleted.bin": content},
		map[string]int64{"/deleted.bin": locatedBytes})

	payload, errObj := unwrapPair(t, fam.hash(handle, stringObj("/deleted.bin"), stringObj("sha256")))
	if errObj != nil {
		t.Fatalf("hashing a truncated chain: %s", errObj.Inspect())
	}
	result := payload.(*object.Hash)

	if !mustHashBoolValue(t, result, "truncated") {
		t.Fatalf("a truncated chain was not reported as truncated")
	}
	if got := mustHashIntValue(t, result, "bytes_hashed"); got != locatedBytes {
		t.Fatalf("hashed %d bytes, want the %d located", got, locatedBytes)
	}
	if got := mustHashStringValue(t, result, "digest"); got != sha256Hex(content[:locatedBytes]) {
		t.Fatalf("the digest covers something other than the located prefix")
	}
	if got := mustHashStringValue(t, result, "digest"); got == sha256Hex(content) {
		t.Fatalf("the digest covers the whole recorded length, which was never read")
	}
}

func TestAWindowIsTheBytesAtThatOffset(t *testing.T) {
	content := rampBytes(70000)

	for _, fam := range streamFamilies() {
		t.Run(fam.name, func(t *testing.T) {
			handle := fam.handle(t, map[string][]byte{"/a.bin": content}, nil)

			for _, window := range []struct{ offset, length int64 }{
				{0, 16},
				{1, 4095},
				{65536, 1024},
				{69999, 1},
			} {
				payload, errObj := unwrapPair(t, fam.readAt(handle, stringObj("/a.bin"),
					intObj(window.offset), intObj(window.length)))
				if errObj != nil {
					t.Fatalf("reading %d bytes at %d: %s", window.length, window.offset, errObj.Inspect())
				}
				got, ok := payload.(*object.Bytes)
				if !ok {
					t.Fatalf("a window is %T, want BYTES", payload)
				}
				want := content[window.offset : window.offset+window.length]
				if !bytes.Equal(got.Value, want) {
					t.Fatalf("the window at %d is not the bytes at %d", window.offset, window.offset)
				}
			}
		})
	}
}

// Walking off the end of a file is how a caller finds the end of it, so it is
// an empty answer rather than a failure.
func TestAWindowPastTheEndOfTheFileIsEmpty(t *testing.T) {
	content := rampBytes(512)

	for _, fam := range streamFamilies() {
		t.Run(fam.name, func(t *testing.T) {
			handle := fam.handle(t, map[string][]byte{"/a.bin": content}, nil)

			payload, errObj := unwrapPair(t, fam.readAt(handle, stringObj("/a.bin"), intObj(512), intObj(128)))
			if errObj != nil {
				t.Fatalf("reading at the end of the file: %s", errObj.Inspect())
			}
			got := payload.(*object.Bytes)
			if len(got.Value) != 0 {
				t.Fatalf("reading past the end returned %d bytes", len(got.Value))
			}
		})
	}
}

func TestAWindowIsShortRatherThanPaddedAtTheEnd(t *testing.T) {
	content := rampBytes(1000)

	fam := streamFamilies()[0]
	handle := fam.handle(t, map[string][]byte{"/a.bin": content}, nil)

	payload, errObj := unwrapPair(t, fam.readAt(handle, stringObj("/a.bin"), intObj(900), intObj(4096)))
	if errObj != nil {
		t.Fatalf("reading the tail: %s", errObj.Inspect())
	}
	got := payload.(*object.Bytes)
	if !bytes.Equal(got.Value, content[900:]) {
		t.Fatalf("the tail window is %d bytes, want the final %d", len(got.Value), 100)
	}
}

// Content the volume says exists and the image cannot produce is the finding.
// A short buffer, or a run of zeroes, would be the same call succeeding.
func TestAWindowPastWhatWasLocatedIsRefusedByBothNumbers(t *testing.T) {
	content := rampBytes(8192)
	const locatedBytes = int64(2048)

	for _, fam := range streamFamilies() {
		t.Run(fam.name, func(t *testing.T) {
			handle := fam.handle(t,
				map[string][]byte{"/deleted.bin": content},
				map[string]int64{"/deleted.bin": locatedBytes})

			_, errObj := unwrapPairNoFatal(fam.readAt(handle, stringObj("/deleted.bin"),
				intObj(locatedBytes), intObj(16)))
			if errObj == nil {
				t.Fatalf("%s read past what could be located", fam.name)
			}
			for _, number := range []string{"2048", "8192"} {
				if !strings.Contains(errObj.Message, number) {
					t.Fatalf("the refusal does not name %s: %s", number, errObj.Message)
				}
			}
		})
	}
}

// A window that straddles the end of the chain stops at it, rather than
// continuing into whatever took over those clusters.
func TestAWindowStopsAtTheEndOfTheChain(t *testing.T) {
	content := rampBytes(8192)
	const locatedBytes = int64(2048)

	fam := streamFamilies()[0]
	handle := fam.handle(t,
		map[string][]byte{"/deleted.bin": content},
		map[string]int64{"/deleted.bin": locatedBytes})

	payload, errObj := unwrapPair(t, fam.readAt(handle, stringObj("/deleted.bin"),
		intObj(2000), intObj(512)))
	if errObj != nil {
		t.Fatalf("reading up to the end of the chain: %s", errObj.Inspect())
	}
	got := payload.(*object.Bytes)
	if !bytes.Equal(got.Value, content[2000:locatedBytes]) {
		t.Fatalf("the window ran past the located bytes: got %d, want %d",
			len(got.Value), locatedBytes-2000)
	}
}

func TestAWindowIsCheckedBeforeAnythingIsRead(t *testing.T) {
	fam := streamFamilies()[0]

	cases := []struct {
		name   string
		offset int64
		length int64
		says   string
	}{
		{"a negative offset", -1, 16, "offset must be >= 0"},
		{"a negative length", 0, -1, "length must be >= 0"},
		{"a window larger than memory", 0, maxInMemoryReadBytes + 1, "in-memory limit"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handle := fam.handle(t, map[string][]byte{"/a.bin": rampBytes(16)}, nil)

			_, errObj := unwrapPairNoFatal(fam.readAt(handle, stringObj("/a.bin"),
				intObj(tc.offset), intObj(tc.length)))
			if errObj == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(errObj.Message, tc.says) {
				t.Fatalf("the refusal for %s reads %q, want it to mention %q", tc.name, errObj.Message, tc.says)
			}
		})
	}
}

func TestAPathThatIsNotInTheImageIsRefused(t *testing.T) {
	for _, fam := range streamFamilies() {
		t.Run(fam.name, func(t *testing.T) {
			handle := fam.handle(t, map[string][]byte{"/a.bin": rampBytes(16)}, nil)
			dest := filepath.Join(t.TempDir(), "out.bin")

			for name, call := range map[string]object.Object{
				"extract": fam.extract(handle, stringObj("/missing.bin"), stringObj(dest)),
				"hash":    fam.hash(handle, stringObj("/missing.bin"), stringObj("sha256")),
				"read_at": fam.readAt(handle, stringObj("/missing.bin"), intObj(0), intObj(16)),
			} {
				if _, errObj := unwrapPairNoFatal(call); errObj == nil {
					t.Fatalf("%s accepted a path the image does not hold", name)
				}
			}
			if _, err := os.Stat(dest); err == nil {
				t.Fatalf("a failed extraction created its destination anyway")
			}
		})
	}
}

// failingReaderSession is a session whose file opens and then fails to read,
// which is the only way to reach the half-written path deliberately.
type failingReaderSession struct {
	fakeNTFSSession
}

type failingReaderAt struct{ after int64 }

func (f failingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= f.after {
		return 0, errors.New("the device stopped answering")
	}
	if remaining := f.after - off; int64(len(p)) > remaining {
		p = p[:remaining]
	}
	for i := range p {
		p[i] = 0x5A
	}
	return len(p), nil
}

func (s *failingReaderSession) OpenReader(string) (fsFileReader, error) {
	return fsFileReader{
		ReaderAt: failingReaderAt{after: 4096},
		Size:     1 << 20,
		Located:  1 << 20,
	}, nil
}

// A prefix left behind under the name of the whole file reads as the whole
// file, and nothing downstream can tell the difference.
func TestAnExtractionThatFailsPartWayLeavesNoFileBehind(t *testing.T) {
	installFakeNTFSBackend(t, &fakeNTFSBackend{session: &failingReaderSession{}})
	handle := streamHandle(t, NtfsOpen)
	dest := filepath.Join(t.TempDir(), "half.bin")

	_, errObj := unwrapPairNoFatal(NtfsExtractFile(handle, stringObj("/a.bin"), stringObj(dest)))
	if errObj == nil {
		t.Fatalf("an extraction that could not be completed reported success")
	}
	if !strings.Contains(errObj.Message, "was removed") {
		t.Fatalf("the failure does not say what became of the partial output: %s", errObj.Message)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("the partial output is still at %s", dest)
	}
}

func TestTheStreamingBuiltinsDeclareTheFieldsTheyReturn(t *testing.T) {
	extractFields := []string{"algorithm", "bytes_written", "dest", "digest", "located_bytes", "path", "size", "truncated"}
	hashFields := []string{"algorithm", "bytes_hashed", "digest", "located_bytes", "path", "size", "truncated"}

	for _, fam := range []string{"Ntfs", "Fat", "Xfat", "Ext", "Hfs", "Xfs"} {
		for name, want := range map[string][]string{
			builtinNameFor(t, fam, "extract_file"): extractFields,
			builtinNameFor(t, fam, "hash_file"):    hashFields,
		} {
			doc, ok := builtinDocs[name]
			if !ok {
				t.Fatalf("%s has no documentation entry", name)
			}
			if len(doc.returns.fields) != len(want) {
				t.Fatalf("%s declares %v, want %v", name, doc.returns.fields, want)
			}
			for i, field := range want {
				if doc.returns.fields[i] != field {
					t.Fatalf("%s declares %v, want %v", name, doc.returns.fields, want)
				}
			}
		}
	}
}

func builtinNameFor(t *testing.T, family, verb string) string {
	t.Helper()
	return strings.ToLower(family) + "_" + verb
}

// The handle resolver each streaming builtin goes through is the one that
// records the touch, so a streamed read appears in the case timeline exactly
// as a whole-file read does.
func TestStreamingAFileIsRecordedInTheCaseTimeline(t *testing.T) {
	openTestCase(t, "IR-STREAM", "G. Gogia")

	installFakeFATBackend(t, &fakeFATBackend{session: &fakeFATSession{
		files: map[string][]byte{"/a.bin": rampBytes(64)},
	}})
	handle := streamHandle(t, FatOpen)

	if _, errObj := unwrapPair(t, FatHashFile(handle, stringObj("/a.bin"), stringObj("sha256"))); errObj != nil {
		t.Fatalf("fat_hash_file: %s", errObj.Inspect())
	}

	evidence := manifestArray(t, currentManifest(t), "evidence")
	if len(evidence) != 1 {
		t.Fatalf("recorded %d evidence sources, want 1", len(evidence))
	}

	rendered := evidence[0].Inspect()
	if !strings.Contains(rendered, BuiltinNameFatHashFile) {
		t.Fatalf("the timeline does not name fat_hash_file: %s", rendered)
	}
}

// ---------------------------------------------------------------------------
// Against the real library.

// writeFATFileEntry puts a file with content into the root of the image
// buildFAT16Image produces, which otherwise holds only a subdirectory. The
// chain is written to every FAT so the volume stays self-consistent.
func writeFATFileEntry(t *testing.T, image []byte, numberOfFATs int, name string, content []byte) {
	t.Helper()

	fatBytes := fatTestFATSectors * fatTestSectorSize
	firstFATOffset := fatTestSectorSize // one reserved sector
	rootOffset := firstFATOffset + numberOfFATs*fatBytes
	dataOffset := rootOffset + fatTestRootDirSector*fatTestSectorSize

	// Cluster 2 already holds the subdirectory, so this file starts at 3.
	const firstCluster = 3
	clusters := (len(content) + fatTestSectorSize - 1) / fatTestSectorSize
	if clusters == 0 {
		clusters = 1
	}
	if firstCluster+clusters > fatTestClusters {
		t.Fatalf("%d bytes do not fit in the test volume", len(content))
	}

	for i := 0; i < clusters; i++ {
		cluster := firstCluster + i
		next := uint16(cluster + 1)
		if i == clusters-1 {
			next = 0xFFFF
		}
		for fat := 0; fat < numberOfFATs; fat++ {
			putUint16LE(image, firstFATOffset+fat*fatBytes+cluster*2, next)
		}

		from := i * fatTestSectorSize
		to := from + fatTestSectorSize
		if to > len(content) {
			to = len(content)
		}
		at := dataOffset + (cluster-2)*fatTestSectorSize
		copy(image[at:at+fatTestSectorSize], content[from:to])
	}

	// The second root entry, immediately after SUBDIR.
	writeFATDirEntry(image[rootOffset+32:], name, 0x20, firstCluster, uint32(len(content)))
}

// This is the test the fakes cannot be: a file of more than two megabytes,
// fragmented across clusters of a real FAT16 volume, streamed out through
// libfat and compared byte for byte -- with nothing ever holding the whole of
// it but the destination file.
func TestARealFileStreamsOutOfARealVolume(t *testing.T) {
	content := rampBytes(streamTestSize)

	image := buildFAT16Image(t, 2, 0)
	writeFATFileEntry(t, image, 2, "EVIDENCEBIN", content)

	path := filepath.Join(t.TempDir(), "volume.img")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatalf("writing the volume: %v", err)
	}

	payload, errObj := unwrapPair(t, FatOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("fat_open: %s", errObj.Inspect())
	}
	opened := payload.(*object.Hash)
	handle := mustHashValue(t, opened, "handle")
	t.Cleanup(func() { FatClose(handle) })

	filePath := onlyFileInRoot(t, handle)

	dest := filepath.Join(t.TempDir(), "extracted.bin")
	payload, errObj = unwrapPair(t, FatExtractFile(handle, stringObj(filePath), stringObj(dest)))
	if errObj != nil {
		t.Fatalf("fat_extract_file: %s", errObj.Inspect())
	}
	result := payload.(*object.Hash)

	written, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("reading the extraction: %v", err)
	}
	if !bytes.Equal(written, content) {
		t.Fatalf("the extracted file differs from the one in the volume (%d vs %d bytes)",
			len(written), len(content))
	}
	if got := mustHashStringValue(t, result, "digest"); got != sha256Hex(content) {
		t.Fatalf("the extraction's digest is not the file's sha256")
	}
	if mustHashBoolValue(t, result, "truncated") {
		t.Fatalf("an intact file in a healthy volume was reported as truncated")
	}

	// The same file hashed where it lies, with nothing written.
	payload, errObj = unwrapPair(t, FatHashFile(handle, stringObj(filePath), stringObj("sha256")))
	if errObj != nil {
		t.Fatalf("fat_hash_file: %s", errObj.Inspect())
	}
	hashed := payload.(*object.Hash)
	if got := mustHashStringValue(t, hashed, "digest"); got != sha256Hex(content) {
		t.Fatalf("hashing in place disagrees with hashing the extracted copy")
	}
	if got := mustHashIntValue(t, hashed, "bytes_hashed"); got != int64(len(content)) {
		t.Fatalf("hashed %d bytes of a %d byte file", got, len(content))
	}

	// And one window out of the middle of it.
	payload, errObj = unwrapPair(t, FatReadFileAt(handle, stringObj(filePath),
		intObj(fsStreamChunkBytes+7), intObj(1024)))
	if errObj != nil {
		t.Fatalf("fat_read_file_at: %s", errObj.Inspect())
	}
	window := payload.(*object.Bytes)
	if !bytes.Equal(window.Value, content[fsStreamChunkBytes+7:fsStreamChunkBytes+7+1024]) {
		t.Fatalf("the window out of the real volume is not the bytes at that offset")
	}
}

func onlyFileInRoot(t *testing.T, handle object.Object) string {
	t.Helper()

	payload, errObj := unwrapPair(t, FatListFiles(handle, stringObj("/")))
	if errObj != nil {
		t.Fatalf("fat_list_files: %s", errObj.Inspect())
	}

	for _, entry := range payload.(*object.Array).Elements {
		row := entry.(*object.Hash)
		if mustHashBoolValue(t, row, "is_dir") {
			continue
		}
		return mustHashStringValue(t, row, "path")
	}

	t.Fatalf("the volume's root holds no file")
	return ""
}

// The reader is the seam, so the contract it carries is asserted directly as
// well as through the builtins.
func TestALocatedLengthNeverExceedsTheRecordedOne(t *testing.T) {
	overreaching := io.NewSectionReader(bytes.NewReader(rampBytes(4096)), 0, 4096)

	if got := locatedSize(overreaching, 1024); got != 1024 {
		t.Fatalf("a reader covering 4096 bytes of a 1024 byte file reported %d", got)
	}
	if got := locatedSize(bytes.NewReader(rampBytes(10)), 10); got != 10 {
		t.Fatalf("a reader covering exactly its file reported %d", got)
	}
	if got := locatedSize(failingReaderAt{}, 512); got != 512 {
		t.Fatalf("a reader carrying no size did not fall back to the recorded one: %d", got)
	}
}
