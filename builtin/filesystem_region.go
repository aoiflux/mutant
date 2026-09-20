package builtin

// Opening a filesystem where it lies.
//
// A partition inside a whole-disk image can now be opened in place. Every one
// of the six libraries behind the fs families accepts a base offset, so an
// examiner no longer has to carve a multi-gigabyte copy out of the evidence
// before reading it.
//
// The base offset goes to the library rather than being handled here by
// wrapping the file in an io.SectionReader, and the reason is not convenience.
// A section reader reads the volume correctly but cannot say where the volume
// sits, so every offset the library then reports is partition-relative -- and a
// partition-relative offset is indistinguishable from an image-absolute one by
// looking at it. Intersecting one against a range expressed against the whole
// image succeeds and is wrong. libntfs, libfat, libhfs and libxfs each say so
// in their own words, which is four independent authors describing one failure
// mode. Passing the base offset instead makes every reported offset absolute
// within the image, so a range from table_list_partitions and a fragment offset
// from ntfs_metadata are in the same coordinate system by construction rather
// than by the script remembering to add something.
//
// A section reader still has one job: bounding the end. A volume opened at a
// partition's start with no length can read past that partition into its
// neighbour and report what it finds as its own. So a region that knows its
// length is wrapped in a section reader running from byte zero -- not from the
// offset, which would move the origin back and undo everything above -- to the
// partition's last byte.

import (
	"fmt"
	"io"
	"os"

	"mutant/object"
)

// fsRegion says which part of a file a filesystem occupies.
//
// The zero value means the whole file is the volume, which is what every fs
// family did before offsets existed and what a carved partition image still
// wants.
type fsRegion struct {
	// Offset is the byte at which the volume's boot record begins.
	Offset int64

	// Length is how many bytes the volume occupies. Zero means the volume runs
	// to the end of the file. That is a different claim from "this volume is
	// zero bytes long", and the two never meet here: a partition entry with a
	// zero length is refused where it is read rather than being quietly widened
	// to the rest of the disk.
	Length int64
}

// bounded reports whether reads past the volume's last byte will fail.
//
// An unbounded volume opened part-way into a disk can read into whatever
// follows it, which is why the open result carries this rather than leaving a
// reader to infer it from a length of zero.
func (r fsRegion) bounded() bool { return r.Length > 0 }

// end is the first byte past the volume, or zero when the region is unbounded.
func (r fsRegion) end() int64 {
	if !r.bounded() {
		return 0
	}
	return r.Offset + r.Length
}

// parseFSOpenArgs reads the (image, offset?, length?) arguments shared by the
// six *_open builtins.
//
// The second argument may be an integer or the partition hash from
// table_list_partitions / table_partition_info. The hash form is the one worth
// using: it carries start_byte and length_byte together, so the two numbers
// cannot be transposed, the length cannot be forgotten, and nothing in the
// script does arithmetic on an offset -- which is the operation every one of
// these libraries warns about.
func parseFSOpenArgs(name string, args []object.Object) (string, fsRegion, *object.Error) {
	if len(args) < 1 || len(args) > 3 {
		return "", fsRegion{}, newError("wrong number of arguments. got=%d, want=1..3", len(args))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return "", fsRegion{}, newError("argument 1 to `%s` must be STRING, got %s", name, args[0].Type())
	}

	if len(args) == 1 {
		return pathObj.Value, fsRegion{}, nil
	}

	switch located := args[1].(type) {
	case *object.Hash:
		if len(args) == 3 {
			return "", fsRegion{}, newError(
				"%s: a partition hash already carries its length, so there is no third argument to give; "+
					"pass explicit integers if the volume is not the whole partition", name)
		}
		region, errObj := fsRegionFromPartition(name, located)
		if errObj != nil {
			return "", fsRegion{}, errObj
		}
		return pathObj.Value, region, nil

	case *object.Integer:
		region := fsRegion{Offset: located.Value}
		if len(args) == 3 {
			lengthObj, ok := args[2].(*object.Integer)
			if !ok {
				return "", fsRegion{}, newError(
					"argument 3 to `%s` must be INTEGER, got %s", name, args[2].Type())
			}
			region.Length = lengthObj.Value
		}
		if errObj := validateFSRegion(name, region); errObj != nil {
			return "", fsRegion{}, errObj
		}
		return pathObj.Value, region, nil

	default:
		return "", fsRegion{}, newError(
			"argument 2 to `%s` must be INTEGER or a partition HASH from table_list_partitions, got %s",
			name, args[1].Type())
	}
}

// fsRegionFromPartition reads a region out of a table_ family partition hash.
//
// It insists on both fields. start_byte alone would open the volume at the
// right place and let it run to the end of the disk, which reads a neighbouring
// partition's bytes and reports them as this volume's -- the exact confusion
// the byte offsets were added to the table_ family to prevent.
func fsRegionFromPartition(name string, h *object.Hash) (fsRegion, *object.Error) {
	start, err := hashIntField(h, "start_byte")
	if err != nil {
		return fsRegion{}, newError(
			"%s: the hash has no INTEGER start_byte, so it is not a partition from "+
				"table_list_partitions or table_partition_info", name)
	}

	length, err := hashIntField(h, "length_byte")
	if err != nil {
		return fsRegion{}, newError(
			"%s: the partition hash has no INTEGER length_byte", name)
	}
	if length == 0 {
		return fsRegion{}, newError(
			"%s: partition at byte %d has a length of zero, so there is no volume to open; "+
				"a zero-length entry is a malformed partition table, and opening it "+
				"unbounded would read the rest of the disk as if it were this partition",
			name, start)
	}

	region := fsRegion{Offset: start, Length: length}
	if errObj := validateFSRegion(name, region); errObj != nil {
		return fsRegion{}, errObj
	}
	return region, nil
}

// validateFSRegion rejects a region that cannot describe a volume, before any
// file is opened. Each library has its own guard against a negative offset;
// catching it here means one message rather than six.
func validateFSRegion(name string, region fsRegion) *object.Error {
	if region.Offset < 0 {
		return newError("%s: offset must be >= 0, got %d", name, region.Offset)
	}
	if region.Length < 0 {
		return newError("%s: length must be >= 0, got %d", name, region.Length)
	}
	return nil
}

// openVolumeRegion opens path and returns the file, the reader the filesystem
// library should be handed, and the size of that reader.
//
// The caller owns the file and must close it, including when the library's own
// open fails. The reader is the file itself when the region is unbounded, and a
// section reader from byte zero to the volume's last byte when it is not.
func openVolumeRegion(path string, region fsRegion) (*os.File, io.ReaderAt, int64, error) {
	img, err := os.Open(path)
	if err != nil {
		return nil, nil, 0, err
	}

	info, err := img.Stat()
	if err != nil {
		_ = img.Close()
		return nil, nil, 0, err
	}
	size := info.Size()

	// Both of these are checked against the image rather than left to the
	// filesystem library, which meets them as an unreadable boot sector and
	// reports a corrupt volume -- a true statement about the wrong thing.
	if region.Offset > 0 && region.Offset >= size {
		_ = img.Close()
		return nil, nil, 0, fmt.Errorf(
			"volume starts at byte %d but the image is %d bytes", region.Offset, size)
	}
	if region.bounded() && region.end() > size {
		_ = img.Close()
		return nil, nil, 0, fmt.Errorf(
			"volume runs to byte %d but the image is %d bytes; the image is shorter than the "+
				"partition table describes -- open with a length of 0 to read what is there",
			region.end(), size)
	}

	if !region.bounded() {
		return img, img, size, nil
	}

	// From zero, not from the offset. A section reader starting at the
	// partition would make the library's reported offsets partition-relative
	// and silently undo the reason the base offset is set at all.
	return img, io.NewSectionReader(img, 0, region.end()), region.end(), nil
}

// fsOpenResult is what every *_open returns: the handle, the image it came
// from, and where in that image the volume was found.
//
// volume_offset is the number that has been added to every byte offset this
// handle will go on to report, so those offsets address the image file itself
// and can be compared with a range from the table_ family without adjustment.
// bounded says whether the volume can read past its own last byte into whatever
// follows it on the disk, which an open with no length can.
func fsOpenResult(handle, volumePath string, region fsRegion) map[string]object.Object {
	return map[string]object.Object{
		"handle":        stringObj(handle),
		"path":          stringObj(volumePath),
		"status":        stringObj("ok"),
		"volume_offset": intObj(region.Offset),
		"volume_length": intObj(region.Length),
		"bounded":       boolObj(region.bounded()),
	}
}
