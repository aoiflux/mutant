package builtin

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// regionFamily is one of the six filesystem families, reduced to the two things
// the region work is about: the builtin a script calls, and a backend that
// records what that call actually asked the library for.
type regionFamily struct {
	name    string
	open    func(...object.Object) object.Object
	install func(t *testing.T, got *fsRegion, path *string)
}

func regionFamilies() []regionFamily {
	return []regionFamily{
		{BuiltinNameNtfsOpen, NtfsOpen, func(t *testing.T, got *fsRegion, path *string) {
			installFakeNTFSBackend(t, &fakeNTFSBackend{session: &fakeNTFSSession{}, opened: got, path: path})
		}},
		{BuiltinNameFatOpen, FatOpen, func(t *testing.T, got *fsRegion, path *string) {
			installFakeFATBackend(t, &fakeFATBackend{session: &fakeFATSession{}, opened: got, path: path})
		}},
		{BuiltinNameXfatOpen, XFATOpen, func(t *testing.T, got *fsRegion, path *string) {
			installFakeXFATBackend(t, &fakeXFATBackend{session: &fakeXFATSession{}, opened: got, path: path})
		}},
		{BuiltinNameExtOpen, ExtOpen, func(t *testing.T, got *fsRegion, path *string) {
			installFakeEXTBackend(t, &fakeEXTBackend{session: &fakeEXTSession{}, opened: got, path: path})
		}},
		{BuiltinNameHfsOpen, HFSOpen, func(t *testing.T, got *fsRegion, path *string) {
			installFakeHFSBackend(t, &fakeHFSBackend{session: &fakeHFSSession{}, opened: got, path: path})
		}},
		{BuiltinNameXfsOpen, XFSOpen, func(t *testing.T, got *fsRegion, path *string) {
			installFakeXFSBackend(t, &fakeXFSBackend{session: &fakeXFSSession{}, opened: got, path: path})
		}},
	}
}

// partitionHash is the shape table_list_partitions hands back, cut down to the
// two fields an open reads out of it.
func partitionHash(start, length int64) *object.Hash {
	return makeHashObject(map[string]object.Object{
		"index":       intObj(1),
		"start_byte":  intObj(start),
		"length_byte": intObj(length),
		"type_name":   stringObj("NTFS / exFAT"),
	})
}

func TestOpeningWithOneArgumentIsWhatItAlwaysWas(t *testing.T) {
	for _, fam := range regionFamilies() {
		t.Run(fam.name, func(t *testing.T) {
			var got fsRegion
			var gotPath string
			fam.install(t, &got, &gotPath)

			payload, errObj := unwrapPair(t, fam.open(stringObj("synthetic.img")))
			if errObj != nil {
				t.Fatalf("%s returned error: %s", fam.name, errObj.Inspect())
			}
			hash := payload.(*object.Hash)

			if got != (fsRegion{}) {
				t.Fatalf("%s passed a region for a one-argument open. got=%+v", fam.name, got)
			}
			if gotPath != "synthetic.img" {
				t.Fatalf("%s passed the wrong path. got=%q", fam.name, gotPath)
			}
			if off := mustHashIntValue(t, hash, "volume_offset"); off != 0 {
				t.Fatalf("%s reported volume_offset %d, want 0", fam.name, off)
			}
			if length := mustHashIntValue(t, hash, "volume_length"); length != 0 {
				t.Fatalf("%s reported volume_length %d, want 0", fam.name, length)
			}
			if mustHashBoolValue(t, hash, "bounded") {
				t.Fatalf("%s reported a one-argument open as bounded", fam.name)
			}
		})
	}
}

func TestTheOffsetAScriptNamesIsTheOffsetTheLibraryIsGiven(t *testing.T) {
	const offset = int64(1048576)
	const length = int64(104857600)

	for _, fam := range regionFamilies() {
		t.Run(fam.name, func(t *testing.T) {
			var got fsRegion
			var gotPath string
			fam.install(t, &got, &gotPath)

			payload, errObj := unwrapPair(t, fam.open(stringObj("disk.raw"), intObj(offset), intObj(length)))
			if errObj != nil {
				t.Fatalf("%s returned error: %s", fam.name, errObj.Inspect())
			}
			hash := payload.(*object.Hash)

			if got.Offset != offset || got.Length != length {
				t.Fatalf("%s handed the backend %+v, want offset %d length %d",
					fam.name, got, offset, length)
			}
			if off := mustHashIntValue(t, hash, "volume_offset"); off != offset {
				t.Fatalf("%s reported volume_offset %d, want %d", fam.name, off, offset)
			}
			if got := mustHashIntValue(t, hash, "volume_length"); got != length {
				t.Fatalf("%s reported volume_length %d, want %d", fam.name, got, length)
			}
			if !mustHashBoolValue(t, hash, "bounded") {
				t.Fatalf("%s reported an open with a length as unbounded", fam.name)
			}
		})
	}
}

func TestAPartitionOpensWhereTheTableSaysItIs(t *testing.T) {
	const start = int64(32256)
	const length = int64(2147483648)

	for _, fam := range regionFamilies() {
		t.Run(fam.name, func(t *testing.T) {
			var got fsRegion
			var gotPath string
			fam.install(t, &got, &gotPath)

			payload, errObj := unwrapPair(t, fam.open(stringObj("disk.raw"), partitionHash(start, length)))
			if errObj != nil {
				t.Fatalf("%s returned error: %s", fam.name, errObj.Inspect())
			}
			hash := payload.(*object.Hash)

			if got.Offset != start || got.Length != length {
				t.Fatalf("%s read the wrong region out of the partition hash. got=%+v", fam.name, got)
			}
			if !mustHashBoolValue(t, hash, "bounded") {
				t.Fatalf("%s opened a partition unbounded; a partition knows its own length", fam.name)
			}
		})
	}
}

// An unbounded open at a non-zero offset can read past the partition into its
// neighbour, so the difference between the two forms is reported rather than
// left for a reader to work out from a length of zero.
func TestAnOffsetWithoutALengthIsNotBounded(t *testing.T) {
	var got fsRegion
	var gotPath string
	installFakeNTFSBackend(t, &fakeNTFSBackend{session: &fakeNTFSSession{}, opened: &got, path: &gotPath})

	payload, errObj := unwrapPair(t, NtfsOpen(stringObj("disk.raw"), intObj(2048)))
	if errObj != nil {
		t.Fatalf("ntfs_open returned error: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)

	if got.Offset != 2048 || got.Length != 0 {
		t.Fatalf("unexpected region. got=%+v", got)
	}
	if mustHashBoolValue(t, hash, "bounded") {
		t.Fatalf("an open with no length reported itself bounded")
	}
}

func TestAPartitionHashRefusesAThirdArgument(t *testing.T) {
	var got fsRegion
	var gotPath string
	installFakeNTFSBackend(t, &fakeNTFSBackend{session: &fakeNTFSSession{}, opened: &got, path: &gotPath})

	_, errObj := unwrapPairNoFatal(NtfsOpen(stringObj("disk.raw"), partitionHash(2048, 4096), intObj(99)))
	if errObj == nil {
		t.Fatalf("ntfs_open accepted a length alongside a partition hash")
	}
	if !strings.Contains(errObj.Message, "already carries its length") {
		t.Fatalf("unexpected message: %s", errObj.Message)
	}
}

func TestAHashThatIsNotAPartitionIsRejected(t *testing.T) {
	var got fsRegion
	var gotPath string
	installFakeNTFSBackend(t, &fakeNTFSBackend{session: &fakeNTFSSession{}, opened: &got, path: &gotPath})

	notAPartition := makeHashObject(map[string]object.Object{
		"start": intObj(2048),
		"size":  intObj(4096),
	})

	_, errObj := unwrapPairNoFatal(NtfsOpen(stringObj("disk.raw"), notAPartition))
	if errObj == nil {
		t.Fatalf("ntfs_open accepted a hash with no start_byte")
	}
	if !strings.Contains(errObj.Message, "start_byte") {
		t.Fatalf("unexpected message: %s", errObj.Message)
	}
}

// A partition entry with no length is a malformed table. Opening it unbounded
// would read the rest of the disk and report it as this partition's contents,
// which is the failure the byte offsets exist to prevent rather than cause.
func TestAZeroLengthPartitionIsNotAVolume(t *testing.T) {
	var got fsRegion
	var gotPath string
	installFakeNTFSBackend(t, &fakeNTFSBackend{session: &fakeNTFSSession{}, opened: &got, path: &gotPath})

	_, errObj := unwrapPairNoFatal(NtfsOpen(stringObj("disk.raw"), partitionHash(2048, 0)))
	if errObj == nil {
		t.Fatalf("ntfs_open accepted a zero-length partition")
	}
	if !strings.Contains(errObj.Message, "length of zero") {
		t.Fatalf("unexpected message: %s", errObj.Message)
	}
	if got != (fsRegion{}) {
		t.Fatalf("the backend was reached despite the refusal. got=%+v", got)
	}
}

func TestARegionIsCheckedBeforeAnyFileIsOpened(t *testing.T) {
	cases := []struct {
		name string
		args []object.Object
		want string
	}{
		{"negative offset", []object.Object{stringObj("disk.raw"), intObj(-1)}, "offset must be >= 0"},
		{"negative length", []object.Object{stringObj("disk.raw"), intObj(0), intObj(-8)}, "length must be >= 0"},
		{"offset is not a number", []object.Object{stringObj("disk.raw"), stringObj("2048")}, "must be INTEGER or a partition HASH"},
		{"length is not a number", []object.Object{stringObj("disk.raw"), intObj(0), stringObj("8")}, "argument 3"},
		{"too many arguments", []object.Object{stringObj("d"), intObj(0), intObj(1), intObj(2)}, "want=1..3"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got fsRegion
			var gotPath string
			installFakeNTFSBackend(t, &fakeNTFSBackend{session: &fakeNTFSSession{}, opened: &got, path: &gotPath})

			_, errObj := unwrapPairNoFatal(NtfsOpen(tc.args...))
			if errObj == nil {
				t.Fatalf("ntfs_open accepted %s", tc.name)
			}
			if !strings.Contains(errObj.Message, tc.want) {
				t.Fatalf("unexpected message: %s", errObj.Message)
			}
			if gotPath != "" {
				t.Fatalf("the backend was reached despite the refusal")
			}
		})
	}
}

// writeRamp writes a file whose byte at every offset is that offset modulo 251,
// so a read can prove which byte of the file it landed on rather than only that
// it read something.
func writeRamp(t *testing.T, size int) string {
	t.Helper()

	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 251)
	}
	path := filepath.Join(t.TempDir(), "ramp.raw")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing ramp: %v", err)
	}
	return path
}

func TestAnUnboundedRegionHandsTheLibraryTheFileItself(t *testing.T) {
	path := writeRamp(t, 512)

	img, reader, size, err := openVolumeRegion(path, fsRegion{})
	if err != nil {
		t.Fatalf("openVolumeRegion: %v", err)
	}
	defer img.Close()

	if reader != io.ReaderAt(img) {
		t.Fatalf("an unbounded region wrapped the file; it should hand the file over as it is")
	}
	if size != 512 {
		t.Fatalf("reported size %d, want 512", size)
	}
}

// The section reader runs from byte zero, not from the partition's start. A
// reader that began at the offset would read the same volume and report every
// offset relative to the partition -- which is the coordinate confusion the
// base offset exists to remove, arriving by the back door.
func TestABoundedRegionDoesNotMoveTheOrigin(t *testing.T) {
	path := writeRamp(t, 512)
	region := fsRegion{Offset: 128, Length: 64}

	img, reader, size, err := openVolumeRegion(path, region)
	if err != nil {
		t.Fatalf("openVolumeRegion: %v", err)
	}
	defer img.Close()

	if size != 192 {
		t.Fatalf("reported size %d, want 192 (the volume's last byte)", size)
	}

	buf := make([]byte, 1)
	if _, err := reader.ReadAt(buf, region.Offset); err != nil {
		t.Fatalf("reading the volume's first byte at its image offset: %v", err)
	}
	if want := byte(128 % 251); buf[0] != want {
		t.Fatalf("byte at image offset 128 is %d, want %d -- the origin moved", buf[0], want)
	}

	if _, err := reader.ReadAt(buf, 0); err != nil {
		t.Fatalf("reading byte 0 of the image: %v", err)
	}
	if buf[0] != 0 {
		t.Fatalf("byte at image offset 0 is %d, want 0", buf[0])
	}
}

func TestABoundedRegionStopsAtTheVolumesLastByte(t *testing.T) {
	path := writeRamp(t, 512)

	img, reader, _, err := openVolumeRegion(path, fsRegion{Offset: 128, Length: 64})
	if err != nil {
		t.Fatalf("openVolumeRegion: %v", err)
	}
	defer img.Close()

	buf := make([]byte, 1)
	if _, err := reader.ReadAt(buf, 191); err != nil {
		t.Fatalf("reading the volume's last byte: %v", err)
	}
	if _, err := reader.ReadAt(buf, 192); err == nil {
		t.Fatalf("read past the volume's end into the next partition")
	}
}

func TestAVolumeCannotStartPastTheEndOfTheImage(t *testing.T) {
	path := writeRamp(t, 512)

	img, _, _, err := openVolumeRegion(path, fsRegion{Offset: 4096})
	if err == nil {
		_ = img.Close()
		t.Fatalf("opened a volume that starts past the end of the image")
	}
	if !strings.Contains(err.Error(), "the image is 512 bytes") {
		t.Fatalf("unexpected message: %v", err)
	}
}

// A partition table can describe a partition the image does not contain, which
// is what a truncated acquisition looks like from the inside. Refusing names
// both numbers; clamping would hand back a volume whose reads fail somewhere
// less informative.
func TestAVolumeCannotRunPastTheEndOfTheImage(t *testing.T) {
	path := writeRamp(t, 512)

	img, _, _, err := openVolumeRegion(path, fsRegion{Offset: 256, Length: 1024})
	if err == nil {
		_ = img.Close()
		t.Fatalf("opened a volume that runs past the end of the image")
	}
	if !strings.Contains(err.Error(), "runs to byte 1280") {
		t.Fatalf("unexpected message: %v", err)
	}
	if !strings.Contains(err.Error(), "length of 0") {
		t.Fatalf("the message does not say what to do instead: %v", err)
	}
}

func TestOpeningAtTheLastByteOfTheImageIsAllowed(t *testing.T) {
	path := writeRamp(t, 512)

	img, _, size, err := openVolumeRegion(path, fsRegion{Offset: 511})
	if err != nil {
		t.Fatalf("openVolumeRegion: %v", err)
	}
	defer img.Close()

	if size != 512 {
		t.Fatalf("reported size %d, want 512", size)
	}
}

func TestTheSixOpensDeclareTheFieldsTheyReturn(t *testing.T) {
	want := []string{"bounded", "handle", "path", "status", "volume_length", "volume_offset"}

	for _, fam := range regionFamilies() {
		t.Run(fam.name, func(t *testing.T) {
			var got fsRegion
			var gotPath string
			fam.install(t, &got, &gotPath)

			payload, errObj := unwrapPair(t, fam.open(stringObj("disk.raw"), intObj(2048), intObj(4096)))
			if errObj != nil {
				t.Fatalf("%s returned error: %s", fam.name, errObj.Inspect())
			}
			hash := payload.(*object.Hash)

			if len(hash.Pairs) != len(want) {
				t.Fatalf("%s returned %d fields, want %d", fam.name, len(hash.Pairs), len(want))
			}
			for _, key := range want {
				if _, ok := hash.Pairs[(&object.String{Value: key}).HashKey()]; !ok {
					t.Fatalf("%s is missing the %s field", fam.name, key)
				}
			}

			doc, ok := builtinDocs[fam.name]
			if !ok {
				t.Fatalf("%s has no metadata entry", fam.name)
			}
			if len(doc.returns.fields) != len(want) {
				t.Fatalf("%s declares %d return fields, returns %d",
					fam.name, len(doc.returns.fields), len(want))
			}
			for i, key := range want {
				if doc.returns.fields[i] != key {
					t.Fatalf("%s declares field %d as %q, want %q",
						fam.name, i, doc.returns.fields[i], key)
				}
			}
		})
	}
}

// embedVolume writes image into a larger file at offset, with filler before and
// after it, and returns the path. The filler is 0xA5 rather than zeroes: a
// volume found in a field of zeroes would be found the same way whether or not
// the base offset did anything, so zeroes would make the test pass for the
// wrong reason.
func embedVolume(t *testing.T, image []byte, offset, trailing int) string {
	t.Helper()

	disk := make([]byte, offset+len(image)+trailing)
	for i := range disk {
		disk[i] = 0xA5
	}
	copy(disk[offset:], image)

	path := filepath.Join(t.TempDir(), "disk.raw")
	if err := os.WriteFile(path, disk, 0o600); err != nil {
		t.Fatalf("writing disk: %v", err)
	}
	return path
}

// This is the test the fakes cannot be: a real FAT16 volume placed a megabyte
// into a larger file, opened through libfat at that offset, and read.
func TestARealVolumeOpensAtItsOffsetInsideALargerImage(t *testing.T) {
	image := buildFAT16Image(t, 2, 0)
	const offset = 1048576
	path := embedVolume(t, image, offset, 4096)

	session, err := realFATBackend{}.Open(path, fsRegion{Offset: offset, Length: int64(len(image))})
	if err != nil {
		t.Fatalf("opening a volume embedded at byte %d: %v", offset, err)
	}
	defer session.Close()

	entries, err := session.ListFiles("/")
	if err != nil {
		t.Fatalf("listing the embedded volume's root: %v", err)
	}
	var found bool
	for _, entry := range entries {
		if entry.Name == "SUBDIR" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the embedded volume's root does not hold SUBDIR. got=%+v", entries)
	}

	// The offset is not merely tolerated: libfat reports the boot sector where
	// it actually sits in the image, which is the whole reason the base offset
	// is passed to the library rather than hidden behind a section reader.
	real, ok := session.(*realFATSession)
	if !ok {
		t.Fatalf("unexpected session type %T", session)
	}
	if got := real.volume.GetBootSector().Offset; got != offset {
		t.Fatalf("libfat reports the boot sector at byte %d, want %d -- the offset is "+
			"partition-relative and every offset from this handle will be too", got, offset)
	}
}

func TestARealVolumeOpensUnboundedAtItsOffset(t *testing.T) {
	image := buildFAT16Image(t, 2, 0)
	const offset = 65536
	path := embedVolume(t, image, offset, 4096)

	session, err := realFATBackend{}.Open(path, fsRegion{Offset: offset})
	if err != nil {
		t.Fatalf("opening an unbounded volume at byte %d: %v", offset, err)
	}
	defer session.Close()

	if _, err := session.ListFiles("/"); err != nil {
		t.Fatalf("listing an unbounded volume's root: %v", err)
	}
}

// The counterpart that gives the test above its meaning: without the offset the
// same file is not a volume at all.
func TestTheSameImageIsNotAVolumeAtOffsetZero(t *testing.T) {
	image := buildFAT16Image(t, 2, 0)
	path := embedVolume(t, image, 1048576, 4096)

	session, err := realFATBackend{}.Open(path, fsRegion{})
	if err == nil {
		_ = session.Close()
		t.Fatal("libfat found a FAT volume in a megabyte of filler")
	}
}

// Two partitions of one disk are two volumes and one path. Before the region
// was recorded, the manifest said "fat_open opened disk.raw" twice, word for
// word, and a reader could not tell a second look at one volume from a first
// look at another.
func TestTheManifestSaysWhichPartitionWasOpened(t *testing.T) {
	openTestCase(t, "IR-REGION", "G. Gogia")

	image := buildFAT16Image(t, 2, 0)
	path := embedVolume(t, image, 1048576, 4096)

	installFakeFATBackend(t, &fakeFATBackend{session: &fakeFATSession{}})

	for _, region := range []fsRegion{{Offset: 1048576, Length: 2048}, {Offset: 2097152, Length: 4096}} {
		if _, errObj := unwrapPair(t, FatOpen(
			stringObj(path), intObj(region.Offset), intObj(region.Length))); errObj != nil {
			t.Fatalf("fat_open at %d: %s", region.Offset, errObj.Inspect())
		}
	}

	evidence := manifestArray(t, currentManifest(t), "evidence")
	if len(evidence) != 1 {
		t.Fatalf("two handles over one file made %d evidence records, want 1", len(evidence))
	}
	source, ok := evidence[0].(*object.Hash)
	if !ok {
		t.Fatalf("evidence record is not a HASH. got=%T", evidence[0])
	}

	opens := manifestArray(t, source, "opens")
	if len(opens) != 2 {
		t.Fatalf("recorded %d opens, want 2", len(opens))
	}

	seen := map[int64]int64{}
	for _, entry := range opens {
		open, ok := entry.(*object.Hash)
		if !ok {
			t.Fatalf("open record is not a HASH. got=%T", entry)
		}
		seen[mustHashIntValue(t, open, "volume_offset")] = mustHashIntValue(t, open, "volume_length")
	}
	if len(seen) != 2 {
		t.Fatalf("the two opens are indistinguishable in the manifest: %+v", seen)
	}
	if seen[1048576] != 2048 || seen[2097152] != 4096 {
		t.Fatalf("the manifest records the wrong regions: %+v", seen)
	}
}

// Every open carries the two fields, so a report template that prints them
// never meets a record that lacks them.
func TestAWholeFileOpenStillRecordsItsRegion(t *testing.T) {
	openTestCase(t, "IR-WHOLE", "G. Gogia")

	path := writeRamp(t, 512)
	installFakeNTFSBackend(t, &fakeNTFSBackend{session: &fakeNTFSSession{}})

	if _, errObj := unwrapPair(t, NtfsOpen(stringObj(path))); errObj != nil {
		t.Fatalf("ntfs_open: %s", errObj.Inspect())
	}

	evidence := manifestArray(t, currentManifest(t), "evidence")
	source := evidence[0].(*object.Hash)
	open := manifestArray(t, source, "opens")[0].(*object.Hash)

	if got := mustHashIntValue(t, open, "volume_offset"); got != 0 {
		t.Fatalf("a whole-file open recorded volume_offset %d, want 0", got)
	}
	if got := mustHashIntValue(t, open, "volume_length"); got != 0 {
		t.Fatalf("a whole-file open recorded volume_length %d, want 0", got)
	}
}
