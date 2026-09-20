package builtin

import (
	"encoding/hex"
	"io"

	"mutant/object"
)

// A file inside an image is reached through this seam rather than through
// ReadFile, which materialises all of it at once. Every one of the six
// filesystem libraries can hand back random access to an open file together
// with the two lengths that matter, so extraction, hashing and windowed reads
// are written once here and each family supplies only the opening.
//
// Size is the length the volume records -- the directory entry's field, or the
// inode's. Located is how many of those bytes the library could actually find
// on disk.
//
// The two differ on a FAT or exFAT entry whose cluster chain was broken when
// the file was deleted: the entry still records the original length, and only
// a prefix of it leads anywhere. Reading as far as Size would return whatever
// now occupies those clusters as though it were this file's content, which is
// the kind of answer that is wrong without looking wrong. So every read here
// stops at Located and the gap is reported rather than filled. The other four
// libraries do not distinguish, and set Located equal to Size.
type fsFileReader struct {
	ReaderAt io.ReaderAt
	Size     int64
	Located  int64
}

// truncated reports that the volume claims more bytes for this file than the
// library could find.
func (r fsFileReader) truncated() bool { return r.Located < r.Size }

// locatedSize asks a reader how many bytes it actually covers.
//
// libfat and libxfat both return a run-backed reader whose Size is the total of
// the runs the chain reached, which is the number that bounds a read. Neither
// type is exported, so the method is asserted for rather than named; a reader
// that does not carry one is one whose library does not distinguish, and the
// recorded size stands.
func locatedSize(r io.ReaderAt, recorded int64) int64 {
	sized, ok := r.(interface{ Size() int64 })
	if !ok {
		return recorded
	}
	located := sized.Size()
	if located < 0 || located > recorded {
		// A reader covering more than the volume claims is not an invitation
		// to read past the recorded length; the file ends where its entry says
		// it ends, and the surplus is the tail of the last cluster.
		return recorded
	}
	return located
}

// fsStreamChunkBytes is how much a stream moves at a time. Large enough that a
// multi-gigabyte file is not copied thirty-two kilobytes at a time, small
// enough that the peak allocation has nothing to do with the size of the
// evidence -- which is the entire point of streaming it.
const fsStreamChunkBytes = 1 << 20

// fsReaderResolver turns a handle argument into an opener over its session.
// Each family supplies one; it is also where the custody touch is recorded,
// because it goes through that family's existing handle resolver.
type fsReaderResolver func(arg object.Object, op string) (fsStreamOpener, *object.Error)

// fsStreamOpener opens one file inside an already-open volume.
type fsStreamOpener func(path string) (fsFileReader, error)

// fsStreamOpen resolves the handle and path arguments shared by all three
// streaming builtins and opens the file they name.
func fsStreamOpen(op string, args []object.Object, resolve fsReaderResolver) (string, fsFileReader, *object.Error) {
	open, errObj := resolve(args[0], op)
	if errObj != nil {
		return "", fsFileReader{}, errObj
	}

	path, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return "", fsFileReader{}, errObj
	}

	reader, err := open(path)
	if err != nil {
		return "", fsFileReader{}, newError("%s: %s", op, err.Error())
	}

	return path, reader, nil
}

// fsStreamSection bounds a reader at the bytes that were actually located.
func fsStreamSection(reader fsFileReader) *io.SectionReader {
	return io.NewSectionReader(reader.ReaderAt, 0, reader.Located)
}

// fsExtractFile streams a file out of an image and onto the local disk without
// ever holding it in memory, recording the digest of what it wrote in the same
// pass so that nothing has to read the file a second time to obtain one.
func fsExtractFile(op string, args []object.Object, resolve fsReaderResolver) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}

	path, reader, errObj := fsStreamOpen(op, args, resolve)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	destination, errObj := requireStringArg(op, args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	// The write, the exclusive create and the single-pass digest are shared
	// with the *_recover_file family: both produce a new piece of evidence
	// out of an image, and there is no reason for two copies of the rule
	// about not overwriting one.
	written, digest, errObj := fsWriteEvidenceFile(op, destination, fsStreamSection(reader))
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":          stringObj(path),
		"dest":          stringObj(destination),
		"size":          intObj(reader.Size),
		"located_bytes": intObj(reader.Located),
		"bytes_written": intObj(written),
		"truncated":     boolObj(reader.truncated()),
		"algorithm":     stringObj("sha256"),
		"digest":        stringObj(digest),
	}), nil)
}

// fsHashFile digests a file inside an image without writing a copy of it
// anywhere, which is what makes a hash-set lookup possible on a file too large
// to read into a mutant value.
func fsHashFile(op string, args []object.Object, resolve fsReaderResolver) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}

	path, reader, errObj := fsStreamOpen(op, args, resolve)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	algorithm, errObj := requireStringArg(op, args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	digest, errObj := fsHashAlgorithm(op, algorithm)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	hashed, err := io.CopyBuffer(digest, fsStreamSection(reader), make([]byte, fsStreamChunkBytes))
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":          stringObj(path),
		"size":          intObj(reader.Size),
		"located_bytes": intObj(reader.Located),
		"bytes_hashed":  intObj(hashed),
		"truncated":     boolObj(reader.truncated()),
		"algorithm":     stringObj(algorithm),
		"digest":        stringObj(hex.EncodeToString(digest.Sum(nil))),
	}), nil)
}

// fsReadFileAt reads one window of a file, so that the header of a file far
// larger than the in-memory ceiling is still reachable from a script.
//
// It returns BYTES and has no text-returning twin: a file recovered from an
// image is binary until something says otherwise, and the string forms of the
// read builtins exist only because they predate the type.
func fsReadFileAt(op string, args []object.Object, resolve fsReaderResolver) object.Object {
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}

	_, reader, errObj := fsStreamOpen(op, args, resolve)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	offset, errObj := requireIntArg(op, args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	length, errObj := requireIntArg(op, args[3], 4)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	if offset < 0 {
		return resultAndError(nil, newError("%s: offset must be >= 0", op))
	}
	if length < 0 {
		return resultAndError(nil, newError("%s: length must be >= 0", op))
	}
	if length > maxInMemoryReadBytes {
		return resultAndError(nil, newError("%s: length %d exceeds the %d byte in-memory limit; stream it instead",
			op, length, maxInMemoryReadBytes))
	}

	// Reading from at or past the recorded end of a file is how a caller walks
	// to the end of one, so it is an empty answer rather than an error.
	if offset >= reader.Size {
		return resultAndError(binaryResult(true, []byte{}), nil)
	}

	// Inside the file, but past what the library could find. This is content
	// the volume says exists and the image cannot produce, and the two numbers
	// are the finding -- returning zeroes or a short buffer would hide it.
	if offset >= reader.Located {
		return resultAndError(nil, newError("%s: offset %d is inside the recorded size %d but past the %d bytes that could be located",
			op, offset, reader.Size, reader.Located))
	}

	if available := reader.Located - offset; length > available {
		length = available
	}

	buffer := make([]byte, length)
	read, err := reader.ReaderAt.ReadAt(buffer, offset)
	if err != nil && err != io.EOF {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}

	return resultAndError(binaryResult(true, buffer[:read]), nil)
}

// Each family's resolver is three lines over its existing handle resolver,
// which is also what records the custody touch.

func ntfsReaderResolver(arg object.Object, op string) (fsStreamOpener, *object.Error) {
	state, errObj := resolveNTFSHandle(arg, op)
	if errObj != nil {
		return nil, errObj
	}
	return state.Session.OpenReader, nil
}

func fatReaderResolver(arg object.Object, op string) (fsStreamOpener, *object.Error) {
	state, errObj := resolveFATHandle(arg, op)
	if errObj != nil {
		return nil, errObj
	}
	return state.Session.OpenReader, nil
}

func xfatReaderResolver(arg object.Object, op string) (fsStreamOpener, *object.Error) {
	state, errObj := resolveXFATHandle(arg, op)
	if errObj != nil {
		return nil, errObj
	}
	return state.Session.OpenReader, nil
}

func extReaderResolver(arg object.Object, op string) (fsStreamOpener, *object.Error) {
	state, errObj := resolveEXTHandle(arg, op)
	if errObj != nil {
		return nil, errObj
	}
	return state.Session.OpenReader, nil
}

func hfsReaderResolver(arg object.Object, op string) (fsStreamOpener, *object.Error) {
	state, errObj := resolveHFSHandle(arg, op)
	if errObj != nil {
		return nil, errObj
	}
	return state.Session.OpenReader, nil
}

func xfsReaderResolver(arg object.Object, op string) (fsStreamOpener, *object.Error) {
	state, errObj := resolveXFSHandle(arg, op)
	if errObj != nil {
		return nil, errObj
	}
	return state.Session.OpenReader, nil
}

func NtfsExtractFile(args ...object.Object) object.Object {
	return fsExtractFile(BuiltinNameNtfsExtractFile, args, ntfsReaderResolver)
}

func NtfsHashFile(args ...object.Object) object.Object {
	return fsHashFile(BuiltinNameNtfsHashFile, args, ntfsReaderResolver)
}

func NtfsReadFileAt(args ...object.Object) object.Object {
	return fsReadFileAt(BuiltinNameNtfsReadFileAt, args, ntfsReaderResolver)
}

func FatExtractFile(args ...object.Object) object.Object {
	return fsExtractFile(BuiltinNameFatExtractFile, args, fatReaderResolver)
}

func FatHashFile(args ...object.Object) object.Object {
	return fsHashFile(BuiltinNameFatHashFile, args, fatReaderResolver)
}

func FatReadFileAt(args ...object.Object) object.Object {
	return fsReadFileAt(BuiltinNameFatReadFileAt, args, fatReaderResolver)
}

func XFATExtractFile(args ...object.Object) object.Object {
	return fsExtractFile(BuiltinNameXfatExtractFile, args, xfatReaderResolver)
}

func XFATHashFile(args ...object.Object) object.Object {
	return fsHashFile(BuiltinNameXfatHashFile, args, xfatReaderResolver)
}

func XFATReadFileAt(args ...object.Object) object.Object {
	return fsReadFileAt(BuiltinNameXfatReadFileAt, args, xfatReaderResolver)
}

func ExtExtractFile(args ...object.Object) object.Object {
	return fsExtractFile(BuiltinNameExtExtractFile, args, extReaderResolver)
}

func ExtHashFile(args ...object.Object) object.Object {
	return fsHashFile(BuiltinNameExtHashFile, args, extReaderResolver)
}

func ExtReadFileAt(args ...object.Object) object.Object {
	return fsReadFileAt(BuiltinNameExtReadFileAt, args, extReaderResolver)
}

func HFSExtractFile(args ...object.Object) object.Object {
	return fsExtractFile(BuiltinNameHfsExtractFile, args, hfsReaderResolver)
}

func HFSHashFile(args ...object.Object) object.Object {
	return fsHashFile(BuiltinNameHfsHashFile, args, hfsReaderResolver)
}

func HFSReadFileAt(args ...object.Object) object.Object {
	return fsReadFileAt(BuiltinNameHfsReadFileAt, args, hfsReaderResolver)
}

func XFSExtractFile(args ...object.Object) object.Object {
	return fsExtractFile(BuiltinNameXfsExtractFile, args, xfsReaderResolver)
}

func XFSHashFile(args ...object.Object) object.Object {
	return fsHashFile(BuiltinNameXfsHashFile, args, xfsReaderResolver)
}

func XFSReadFileAt(args ...object.Object) object.Object {
	return fsReadFileAt(BuiltinNameXfsReadFileAt, args, xfsReaderResolver)
}
