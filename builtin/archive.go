package builtin

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"

	"mutant/object"
)

// Evidence arrives compressed. A KAPE, CyLR or Velociraptor collection is a
// .zip; a Linux triage script hands back a .tar.gz. Until now the language
// could decompress a single gzip stream and nothing else, which meant an
// analyst had to leave it to unpack a container before any of the parsing
// builtins could see inside.
//
// The two families here read those containers in place. Neither writes to
// disk: an archive is read for what it contains, and the entry a program wants
// goes straight into a BYTES buffer for bin_*, fs_hash_data, evtx_parse or
// whatever comes next. That also means the classic extraction vulnerability --
// an entry named ../../etc/passwd escaping the destination directory -- cannot
// be exploited through these builtins at all. It is still worth knowing about,
// so every entry carries an unsafe_path flag: an archive that contains such a
// name is itself a finding.

// The other half of reading a container safely is refusing to be a decompression
// bomb's victim. A 42 KB zip that expands to 4.5 PB is a real artifact, not a
// thought experiment, and an evidence container is exactly where one would be
// hidden -- it costs an attacker nothing to leave one in a collection they
// expect to be triaged.
//
// The defence is one number: how many bytes a single decompression call may
// produce. It is derived rather than fixed, because neither a pure ratio nor a
// pure absolute cap works alone. A ratio alone rejects legitimate data --
// a sparse disk image or a repetitive log compresses far past any ratio a bomb
// would need to beat. An absolute cap alone lets a small bomb through whenever
// the cap is generous enough to be useful.
//
// So the limit is min(compressed x maxDecompressionRatio, maxDecompressedBytes),
// and the caller can name its own limit when it knows better. That last part is
// deliberate: the analyst who genuinely needs a 4 GB image out of a container
// should be able to say so in the program, in the open, rather than discover
// that the language cannot do it.
const (
	// maxDecompressionRatio bounds output against input. 1000:1 is far above
	// what general-purpose data reaches and far below what a bomb needs.
	maxDecompressionRatio = 1000

	// maxDecompressedBytes is the ceiling regardless of ratio.
	maxDecompressedBytes = 1 << 30 // 1 GiB
)

// errDecompressionLimit is what a program sees when a stream ran past its
// limit. The message names the limit and how to raise it, because "too large"
// with no number is not actionable.
var errDecompressionLimit = errors.New("decompression limit exceeded")

// decompressionLimit returns how many bytes a stream of the given compressed
// size may expand to. compressed <= 0 means the size is unknown, which leaves
// only the absolute ceiling.
func decompressionLimit(compressed int64) int64 {
	if compressed <= 0 {
		return maxDecompressedBytes
	}
	if compressed > maxDecompressedBytes/maxDecompressionRatio {
		return maxDecompressedBytes
	}
	return compressed * maxDecompressionRatio
}

// resolveDecompressionLimit applies a caller's explicit limit when one was
// given, and derives one otherwise. An explicit limit replaces the derived one
// outright rather than being clamped by it -- a caller that names a number has
// made the decision the default exists to make on its behalf.
func resolveDecompressionLimit(op string, args []object.Object, pos int, compressed int64) (int64, *object.Error) {
	if len(args) < pos {
		return decompressionLimit(compressed), nil
	}
	limit, errObj := requireIntArg(op, args[pos-1], pos)
	if errObj != nil {
		return 0, errObj
	}
	if limit <= 0 {
		return 0, newError("argument %d to `%s` must be a positive byte limit, got %d", pos, op, limit)
	}
	return limit, nil
}

// readLimited reads r to EOF, refusing to hold more than limit bytes.
//
// It reads one byte past the limit rather than checking as it goes, because
// that is the only way to tell "exactly at the limit" from "ran over it"
// without trusting a declared size.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: stream expands past %d bytes (pass an explicit max_bytes to raise it)",
			errDecompressionLimit, limit)
	}
	return data, nil
}

// unsafeArchivePath reports whether an entry name would escape the directory it
// was extracted into: an absolute path, a drive-letter or UNC path, or one that
// climbs out with "..".
//
// Nothing here extracts, so this cannot be exploited through these builtins.
// It is reported because an archive containing such a name is a finding in its
// own right -- it is how a collection gets weaponised against the tool that
// opens it.
func unsafeArchivePath(name string) bool {
	if name == "" {
		return false
	}
	normalized := strings.ReplaceAll(name, `\`, "/")
	if strings.HasPrefix(normalized, "/") || strings.HasPrefix(normalized, "//") {
		return true
	}
	// A Windows drive letter, which path.Clean does not understand.
	if len(normalized) >= 2 && normalized[1] == ':' {
		return true
	}
	cleaned := path.Clean(normalized)
	return cleaned == ".." || strings.HasPrefix(cleaned, "../")
}

// unsafeLinkTarget reports whether a symbolic link at name, pointing at target,
// resolves outside the extraction root: an absolute target, or a relative one
// that climbs past the root from the link's own directory.
//
// A relative target is read from where the link sits, as every extractor reads
// it. Judged from the archive root instead, usr/lib/libfoo.so -> ../lib64/x --
// an ordinary link in any root filesystem -- was flagged (M26-DAT-007).
func unsafeLinkTarget(name, target string) bool {
	if target == "" {
		return false
	}
	normalized := strings.ReplaceAll(target, `\`, "/")
	if strings.HasPrefix(normalized, "/") || (len(normalized) >= 2 && normalized[1] == ':') {
		return true
	}
	dir := path.Dir(strings.ReplaceAll(name, `\`, "/"))
	return unsafeArchivePath(path.Join(dir, normalized))
}

// maxZipLinkTargetBytes bounds how much of a zip symlink entry's body is read
// to learn where the link points. It is PATH_MAX on Linux, the longest target
// a link can be created with there.
//
//mutant:limit bytes
const maxZipLinkTargetBytes = 4096

// unsafeZipEntry reports whether extracting one zip entry would write outside
// the root: through its own name, or -- for a symbolic link, whose target is
// its body -- through where it points. Only the name used to be checked, which
// is the half the comment above unsafeTarMember says gets forgotten
// (M26-DAT-007). A link whose target cannot be read, or runs past
// maxZipLinkTargetBytes, is counted as unsafe: nothing then vouches for where
// it points.
func unsafeZipEntry(entry *zip.File) bool {
	if unsafeArchivePath(entry.Name) {
		return true
	}
	if entry.Mode()&os.ModeSymlink == 0 {
		return false
	}
	rc, err := entry.Open()
	if err != nil {
		return true
	}
	defer rc.Close()
	target, err := io.ReadAll(io.LimitReader(rc, maxZipLinkTargetBytes+1))
	if err != nil || len(target) > maxZipLinkTargetBytes {
		return true
	}
	return unsafeLinkTarget(entry.Name, string(target))
}

// archiveMemberIndex resolves the member a script names -- by its position in
// the listing, or by name -- among names, which is the listing in order.
//
// A name picks out a member only when exactly one carries it. Two members may
// share a name -- a tar appended to with `tar -r` holds every version of a
// file it was given -- and a read used to return the first silently, which for
// an appended tar is the stale one. Such a name is refused, and the member is
// read by position instead. A name matches exactly first; one written with
// backslashes matches its slash spelling only when that, too, is unique.
func archiveMemberIndex(op, archive string, names []string, arg object.Object) (int, *object.Error) {
	switch v := arg.(type) {
	case *object.Integer:
		if v.Value < 0 || v.Value >= int64(len(names)) {
			return 0, newError("%s: member %d is out of range: %s holds %d, numbered from 0 in the order its listing gives", op, v.Value, archive, len(names))
		}
		return int(v.Value), nil
	case *object.String:
		for _, match := range []func(string) bool{
			func(n string) bool { return n == v.Value },
			func(n string) bool { return strings.ReplaceAll(n, `\`, "/") == strings.ReplaceAll(v.Value, `\`, "/") },
		} {
			found := -1
			for i, n := range names {
				if !match(n) {
					continue
				}
				if found >= 0 {
					return 0, newError("%s: more than one entry in %s is named %q (members %d and %d at least); read one by its position in the listing", op, archive, v.Value, found, i)
				}
				found = i
			}
			if found >= 0 {
				return found, nil
			}
		}
		return 0, newError("%s: no entry named %q in %s", op, v.Value, archive)
	default:
		return 0, newError("argument 2 to `%s` must be a STRING name or an INTEGER position, got %s", op, arg.Type())
	}
}

// registerZipDecompressors teaches a zip reader the methods archive/zip does
// not carry. Store (0) and deflate (8) are built in; these two turn up in real
// collections because the tools that produce them offer better ratios than
// deflate and analysts turn them on.
//
// Both come from packages already linked into this binary, so neither costs a
// dependency: bzip2 is in the standard library and zstd arrives with
// klauspost/compress, which the build already uses.
func registerZipDecompressors(r *zip.Reader) {
	const (
		methodBzip2 = 12
		methodZstd  = 93
	)

	r.RegisterDecompressor(methodBzip2, func(in io.Reader) io.ReadCloser {
		return io.NopCloser(bzip2.NewReader(in))
	})
	r.RegisterDecompressor(methodZstd, func(in io.Reader) io.ReadCloser {
		dec, err := zstd.NewReader(in, zstd.WithDecoderConcurrency(1))
		if err != nil {
			// The signature has nowhere to put an error, so hand back a reader
			// that reports it on the first Read rather than a nil that panics.
			return io.NopCloser(errReader{err})
		}
		return dec.IOReadCloser()
	})
}

// errReader fails on every read with a fixed error.
type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// zipMethodName renders a zip compression method as the name an analyst would
// recognise, falling back to the number for anything unnamed -- which is itself
// worth seeing, since an unusual method is a reason to look closer.
func zipMethodName(method uint16) string {
	switch method {
	case zip.Store:
		return "store"
	case zip.Deflate:
		return "deflate"
	case 9:
		return "deflate64"
	case 12:
		return "bzip2"
	case 14:
		return "lzma"
	case 93:
		return "zstd"
	case 95:
		return "xz"
	case 99:
		return "aes"
	default:
		return fmt.Sprintf("method-%d", method)
	}
}

// archiveUnix renders a timestamp the way the rest of the language does, and
// reports a missing one as 0 rather than as the year 1.
func archiveUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

type zipHandleState struct {
	Path   string
	Reader *zip.ReadCloser
	// Unsafe holds unsafeZipEntry for each entry, in Reader.File's order.
	// It is worked out once at open, since a symlink's verdict means reading
	// its body.
	Unsafe []bool
}

// zipEntryNames lists an archive's entry names in Reader.File's order.
func zipEntryNames(reader *zip.ReadCloser) []string {
	names := make([]string, len(reader.File))
	for i, entry := range reader.File {
		names[i] = entry.Name
	}
	return names
}

var zipStore = struct {
	sync.RWMutex
	nextID  int64
	handles map[string]zipHandleState
}{
	handles: map[string]zipHandleState{},
}

// ZipOpen opens a zip archive and returns a handle for the other zip_ builtins.
//
// The archive stays open behind the reader rather than being read into memory,
// so opening a 40 GB collection costs the central directory and nothing more.
// Release it with zip_close.
func ZipOpen(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	archivePath, errObj := requireStringArg(BuiltinNameZipOpen, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return resultAndError(nil, newError("zip_open: %s", err.Error()))
	}
	registerZipDecompressors(&reader.Reader)

	unsafeCount := 0
	unsafe := make([]bool, len(reader.File))
	var totalUncompressed int64
	for i, entry := range reader.File {
		if unsafe[i] = unsafeZipEntry(entry); unsafe[i] {
			unsafeCount++
		}
		totalUncompressed += int64(entry.UncompressedSize64)
	}

	handleID := atomic.AddInt64(&zipStore.nextID, 1)
	handle := fmt.Sprintf("zip-handle-%d", handleID)

	zipStore.Lock()
	zipStore.handles[handle] = zipHandleState{Path: archivePath, Reader: reader, Unsafe: unsafe}
	zipStore.Unlock()

	custodyRecordOpen(BuiltinNameZipOpen, handle, archivePath)

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle":             stringObj(handle),
		"path":               stringObj(archivePath),
		"entry_count":        intObj(int64(len(reader.File))),
		"comment":            stringObj(reader.Comment),
		"total_uncompressed": intObj(totalUncompressed),
		"unsafe_path_count":  intObj(int64(unsafeCount)),
		"status":             stringObj("ok"),
	}), nil)
}

// ZipEntries lists what an archive contains, without decompressing any of it.
func ZipEntries(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	state, errObj := resolveZipHandle(args[0], BuiltinNameZipEntries)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	entries := make([]object.Object, 0, len(state.Reader.File))
	for i, entry := range state.Reader.File {
		entries = append(entries, makeHashObject(map[string]object.Object{
			"name":            stringObj(entry.Name),
			"size":            intObj(int64(entry.UncompressedSize64)),
			"compressed_size": intObj(int64(entry.CompressedSize64)),
			"method":          stringObj(zipMethodName(entry.Method)),
			"is_dir":          boolObj(entry.FileInfo().IsDir()),
			"crc32":           intObj(int64(entry.CRC32)),
			"mode":            stringObj(entry.Mode().String()),
			"modified":        intObj(archiveUnix(entry.Modified)),
			"comment":         stringObj(entry.Comment),
			"encrypted":       boolObj(entry.Flags&0x1 != 0),
			"unsafe_path":     boolObj(state.Unsafe[i]),
		}))
	}

	return resultAndError(&object.Array{Elements: entries}, nil)
}

// ZipRead reads one entry as text, and ZipReadBytes reads it as a buffer. The
// pair shares one implementation and differs only in the type it hands back.
//
// An archive entry is compressed data, which has no reason to be text, so the
// Bytes form is the right one for nearly every caller. The text form exists so
// the family reads like every other reader in the language.
func ZipRead(args ...object.Object) object.Object {
	return zipRead(args, BuiltinNameZipRead, false)
}

func ZipReadBytes(args ...object.Object) object.Object {
	return zipRead(args, BuiltinNameZipReadBytes, true)
}

func zipRead(args []object.Object, opName string, binary bool) object.Object {
	if len(args) < 2 || len(args) > 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}

	state, errObj := resolveZipHandle(args[0], opName)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	index, errObj := archiveMemberIndex(opName, state.Path, zipEntryNames(state.Reader), args[1])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	entry := state.Reader.File[index]
	name := entry.Name
	if entry.FileInfo().IsDir() {
		return resultAndError(nil, newError("%s: %q is a directory", opName, name))
	}

	limit, errObj := resolveDecompressionLimit(opName, args, 3, int64(entry.CompressedSize64))
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	// The central directory declares an uncompressed size, which is worth
	// checking first: it rejects an oversized entry before a byte is
	// decompressed. It is not worth trusting, though -- the declared size is
	// attacker-controlled and a bomb simply lies about it -- so readLimited
	// enforces the same limit against what actually comes out.
	if declared := int64(entry.UncompressedSize64); declared > limit {
		return resultAndError(nil, newError("%s: %q declares %d bytes, past the %d-byte limit "+
			"(pass an explicit max_bytes to raise it)", opName, name, declared, limit))
	}

	rc, err := entry.Open()
	if err != nil {
		return resultAndError(nil, newError("%s: %s: %s", opName, name, err.Error()))
	}
	defer rc.Close()

	data, err := readLimited(rc, limit)
	if err != nil {
		return resultAndError(nil, newError("%s: %s: %s", opName, name, err.Error()))
	}

	return resultAndError(binaryResult(binary, data), nil)
}

// ZipClose releases a handle and the archive file behind it.
func ZipClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	handleObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `zip_close` must be STRING handle, got %s", args[0].Type()))
	}

	zipStore.Lock()
	state, exists := zipStore.handles[handleObj.Value]
	if exists {
		delete(zipStore.handles, handleObj.Value)
	}
	zipStore.Unlock()

	if !exists {
		return resultAndError(nil, newError("zip_close: unknown zip handle: %s", handleObj.Value))
	}

	custodyRecordTouch(BuiltinNameZipClose, handleObj.Value)

	if err := state.Reader.Close(); err != nil {
		return resultAndError(nil, newError("zip_close: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handleObj.Value),
		"closed": boolObj(true),
		"status": stringObj("ok"),
	}), nil)
}

func resolveZipHandle(arg object.Object, op string) (zipHandleState, *object.Error) {
	handleObj, ok := arg.(*object.String)
	if !ok {
		return zipHandleState{}, newError("argument 1 to `%s` must be STRING handle, got %s", op, arg.Type())
	}

	zipStore.RLock()
	state, exists := zipStore.handles[handleObj.Value]
	zipStore.RUnlock()
	if !exists {
		return zipHandleState{}, newError("%s: unknown zip handle: %s", op, handleObj.Value)
	}

	custodyRecordTouch(op, handleObj.Value)

	return state, nil
}

// cappedReader fails once a stream has produced more than it was allowed to.
//
// It exists for the discarding case -- scanning a tar without holding it -- where
// io.LimitReader is the wrong tool: hitting a LimitReader's end looks like a
// clean EOF, so a truncated archive and a bomb that ran out its budget would be
// reported identically. Here the difference is an error that says which.
type cappedReader struct {
	r         io.Reader
	remaining int64
	limit     int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, fmt.Errorf("%w: stream expands past %d bytes", errDecompressionLimit, c.limit)
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	return n, err
}

func newCappedReader(r io.Reader, limit int64) *cappedReader {
	return &cappedReader{r: r, remaining: limit, limit: limit}
}

// maxArchiveEntries bounds how many members a single archive may declare.
// A large collection runs to hundreds of thousands; a stream engineered to
// never end runs to as many as you will read.
const maxArchiveEntries = 1 << 20

// archiveCompression names the outer compression wrapping a tar stream, and
// wraps a reader in the matching decompressor.
//
// Detection is by magic rather than by extension, because the extension on a
// piece of evidence is whatever the last tool to touch it chose, and a .tar
// that is really a .tar.gz should still open.
type archiveCompression struct {
	name  string
	magic []byte
	// wrap returns a decompressor that must be closed: a zstd decoder left
	// open kept reading the archive from its own goroutines, and raced the
	// next read's seek on the same file (M26-DAT-005).
	wrap func(io.Reader) (io.ReadCloser, error)
}

var archiveCompressions = []archiveCompression{
	{
		name:  "gzip",
		magic: []byte{0x1f, 0x8b},
		wrap:  func(r io.Reader) (io.ReadCloser, error) { return gzip.NewReader(r) },
	},
	{
		name:  "bzip2",
		magic: []byte("BZh"),
		wrap:  func(r io.Reader) (io.ReadCloser, error) { return io.NopCloser(bzip2.NewReader(r)), nil },
	},
	{
		name:  "zstd",
		magic: []byte{0x28, 0xb5, 0x2f, 0xfd},
		wrap: func(r io.Reader) (io.ReadCloser, error) {
			// One decoder, decoding as it is read: a walk is sequential, and a
			// decoder that reads ahead on its own goroutines is reading a file
			// the next walk will seek.
			dec, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1))
			if err != nil {
				return nil, err
			}
			return dec.IOReadCloser(), nil
		},
	},
	{
		// Recognised so the failure names the format rather than reporting an
		// unreadable tar. Decoding it would mean a new dependency.
		name:  "xz",
		magic: []byte{0xfd, '7', 'z', 'X', 'Z', 0x00},
		wrap: func(io.Reader) (io.ReadCloser, error) {
			return nil, errors.New("xz-compressed archives are not supported; decompress with `xz -d` first")
		},
	},
}

// The header block a plain tar begins with, as POSIX lays it out: 512 bytes,
// with the header's checksum in the eight bytes at 148, summed with those eight
// read as spaces.
//
//mutant:format POSIX.1-1988 ustar header block (IEEE Std 1003.1, pax "ustar Interchange Format")
const (
	tarBlockSize      = 512
	tarChecksumOffset = 148
	tarChecksumLength = 8
)

// tarHeaderBlock reports whether block is a tar header whose checksum adds up,
// the test archive/tar itself applies. It accepts the signed sum too, which
// some old tar writers produced.
func tarHeaderBlock(block []byte) bool {
	if len(block) < tarBlockSize {
		return false
	}
	field := strings.Trim(string(block[tarChecksumOffset:tarChecksumOffset+tarChecksumLength]), " \x00")
	want, err := strconv.ParseInt(field, 8, 64)
	if err != nil {
		return false
	}
	var unsigned, signed int64
	for i, c := range block[:tarBlockSize] {
		if i >= tarChecksumOffset && i < tarChecksumOffset+tarChecksumLength {
			c = ' '
		}
		unsigned += int64(c)
		signed += int64(int8(c))
	}
	return want == unsigned || want == signed
}

// detectArchiveCompression sniffs the head of a file and returns the matching
// compression, or nil for an uncompressed stream. The file is left positioned
// at the start either way.
//
// A plain tar begins with its first member's name, so a member called
// "BZhistory.txt" carries bzip2's magic; it was refused as broken bzip2
// (M26-DAT-008). A first block that is a valid tar header is therefore
// recognised first. A compressed stream's first 512 bytes do not add up to
// the checksum they hold short of a file built to be read both ways.
func detectArchiveCompression(f *os.File) (*archiveCompression, error) {
	head := make([]byte, tarBlockSize)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	head = head[:n]
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if tarHeaderBlock(head) {
		return nil, nil
	}
	for i := range archiveCompressions {
		if bytes.HasPrefix(head, archiveCompressions[i].magic) {
			return &archiveCompressions[i], nil
		}
	}
	return nil, nil
}

type tarHandleState struct {
	Path        string
	Compression string
	Size        int64
	// WalkLimit bounds the decompressed stream every walk of this archive
	// reads: the one tar_open makes, and every read after it. A read walks the
	// same stream the open walked in full, so it can never need more.
	WalkLimit int64
	File      *os.File
	Mu        *sync.Mutex
	Entries   []tarMember
}

// tarMember is what the walk keeps of one member: the fields tar_entries lists
// and nothing else. A *tar.Header also holds every PAX record the member
// carried, and keeping the headers themselves held 40 MiB for a 44 KB archive
// (M26-DAT-010).
type tarMember struct {
	Name, Linkname, Uname, Gname    string
	Size, Mode                      int64
	Uid, Gid                        int
	Typeflag                        byte
	ModTime, AccessTime, ChangeTime time.Time
}

// maxArchiveListingBytes bounds the text a tar listing holds: every member's
// name, link target, user and group, added up. A collection of a million
// members averaging 128 bytes of it fits; a 44 KB archive of PAX records
// naming members a megabyte long does not.
//
//mutant:limit bytes
const maxArchiveListingBytes = 128 << 20

var tarStore = struct {
	sync.RWMutex
	nextID  int64
	handles map[string]tarHandleState
}{
	handles: map[string]tarHandleState{},
}

// tarStreamReader is a capped decompressed stream that closes its decompressor.
type tarStreamReader struct {
	*cappedReader
	io.Closer
}

// tarStream positions the archive at its start and returns a reader over the
// decompressed tar, capped at the handle's walk limit so a stream engineered
// never to end cannot be walked forever. The caller closes it.
//
// The cap is a ratio by default, and not the absolute one a read uses, and the
// difference is deliberate. Walking discards what it decompresses, so memory
// is not the risk -- time is, and time is bounded by output relative to the
// input the analyst already chose to open. An absolute ceiling would instead
// reject the ordinary case of a 500 MB collection expanding to several
// gigabytes; and tar_open's max_bytes replaces the ratio for an archive that
// compresses past it.
func tarStream(state tarHandleState) (io.ReadCloser, error) {
	if _, err := state.File.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if state.Compression == "none" {
		return io.NopCloser(state.File), nil
	}
	for i := range archiveCompressions {
		if archiveCompressions[i].name != state.Compression {
			continue
		}
		wrapped, err := archiveCompressions[i].wrap(state.File)
		if err != nil {
			return nil, err
		}
		return tarStreamReader{cappedReader: newCappedReader(wrapped, state.WalkLimit), Closer: wrapped}, nil
	}
	return nil, fmt.Errorf("unknown compression %q", state.Compression)
}

// TarOpen opens a tar archive -- plain, or wrapped in gzip, bzip2 or zstd --
// and returns a handle for the other tar_ builtins.
//
// The whole archive is walked once here to record what it contains, because tar
// has no central directory: the only way to know an archive's members is to read
// past every one of them. Bodies are skipped rather than held; what is held is
// the listing, bounded by maxArchiveListingBytes. The file stays open until
// tar_close, which both makes reads cheap and pins the evidence: an archive
// cannot be swapped underneath a running analysis.
//
// The walk of a compressed archive is capped at 1000 times the archive's size
// unless max_bytes names another cap. The cap was fixed, so a collection that
// compresses past it -- a sparse image, a repetitive log -- could not be opened
// at all (M26-DAT-006).
func TarOpen(args ...object.Object) object.Object {
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}

	archivePath, errObj := requireStringArg(BuiltinNameTarOpen, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	var explicitLimit int64
	if len(args) == 2 {
		limit, errObj := requireIntArg(BuiltinNameTarOpen, args[1], 2)
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		if limit <= 0 {
			return resultAndError(nil, newError("argument 2 to `tar_open` must be a positive byte limit, got %d", limit))
		}
		explicitLimit = limit
	}

	file, err := os.Open(archivePath)
	if err != nil {
		return resultAndError(nil, newError("tar_open: %s", err.Error()))
	}

	info, err := file.Stat()
	if err != nil {
		file.Close()
		return resultAndError(nil, newError("tar_open: %s", err.Error()))
	}

	compression, err := detectArchiveCompression(file)
	if err != nil {
		file.Close()
		return resultAndError(nil, newError("tar_open: %s", err.Error()))
	}
	name := "none"
	if compression != nil {
		name = compression.name
	}

	walkLimit := info.Size() * maxDecompressionRatio
	if explicitLimit > 0 {
		walkLimit = explicitLimit
	}
	state := tarHandleState{
		Path:        archivePath,
		Compression: name,
		Size:        info.Size(),
		WalkLimit:   walkLimit,
		File:        file,
		Mu:          &sync.Mutex{},
	}

	entries, err := scanTarEntries(state)
	if err != nil {
		file.Close()
		return resultAndError(nil, newError("tar_open: %s", err.Error()))
	}
	state.Entries = entries

	unsafeCount := 0
	var total int64
	for _, entry := range entries {
		if unsafeTarMember(entry) {
			unsafeCount++
		}
		total += entry.Size
	}

	handleID := atomic.AddInt64(&tarStore.nextID, 1)
	handle := fmt.Sprintf("tar-handle-%d", handleID)

	tarStore.Lock()
	tarStore.handles[handle] = state
	tarStore.Unlock()

	custodyRecordOpen(BuiltinNameTarOpen, handle, archivePath)

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle":             stringObj(handle),
		"path":               stringObj(archivePath),
		"compression":        stringObj(name),
		"entry_count":        intObj(int64(len(entries))),
		"total_uncompressed": intObj(total),
		"unsafe_path_count":  intObj(int64(unsafeCount)),
		"status":             stringObj("ok"),
	}), nil)
}

func scanTarEntries(state tarHandleState) ([]tarMember, error) {
	stream, err := tarStream(state)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	reader := tar.NewReader(stream)
	entries := make([]tarMember, 0, 64)
	var listing int64
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(entries) >= maxArchiveEntries {
			return nil, fmt.Errorf("archive declares more than %d entries", maxArchiveEntries)
		}
		listing += int64(len(header.Name) + len(header.Linkname) + len(header.Uname) + len(header.Gname))
		if listing > maxArchiveListingBytes {
			return nil, fmt.Errorf("the archive's member names, link targets and owners run past %d bytes", maxArchiveListingBytes)
		}
		entries = append(entries, tarMember{
			Name: header.Name, Linkname: header.Linkname, Uname: header.Uname, Gname: header.Gname,
			Size: header.Size, Mode: header.Mode, Uid: header.Uid, Gid: header.Gid, Typeflag: header.Typeflag,
			ModTime: header.ModTime, AccessTime: header.AccessTime, ChangeTime: header.ChangeTime,
		})
	}
	return entries, nil
}

// unsafeTarMember reports a member that would escape its destination on
// extraction -- through its own name, or through where a link points, which is
// the half of the problem that gets forgotten. A symbolic link's target is read
// from the link's own directory; a hard link's names another member, so it is
// read from the archive root.
func unsafeTarMember(entry tarMember) bool {
	if unsafeArchivePath(entry.Name) {
		return true
	}
	switch entry.Typeflag {
	case tar.TypeSymlink:
		return unsafeLinkTarget(entry.Name, entry.Linkname)
	case tar.TypeLink:
		return unsafeArchivePath(entry.Linkname)
	}
	return false
}

// tarEntryType names a tar type flag the way a reader would describe it.
func tarEntryType(flag byte) string {
	switch flag {
	case tar.TypeReg:
		return "file"
	case tar.TypeDir:
		return "dir"
	case tar.TypeSymlink:
		return "symlink"
	case tar.TypeLink:
		return "hardlink"
	case tar.TypeChar:
		return "char-device"
	case tar.TypeBlock:
		return "block-device"
	case tar.TypeFifo:
		return "fifo"
	case tar.TypeXHeader, tar.TypeXGlobalHeader:
		return "pax-header"
	default:
		return fmt.Sprintf("type-%q", rune(flag))
	}
}

// TarEntries lists what an archive contains, from the walk tar_open already did.
func TarEntries(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	state, errObj := resolveTarHandle(args[0], BuiltinNameTarEntries)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	entries := make([]object.Object, 0, len(state.Entries))
	for _, entry := range state.Entries {
		entries = append(entries, makeHashObject(map[string]object.Object{
			"name":        stringObj(entry.Name),
			"size":        intObj(entry.Size),
			"type":        stringObj(tarEntryType(entry.Typeflag)),
			"linkname":    stringObj(entry.Linkname),
			"mode":        intObj(entry.Mode),
			"uid":         intObj(int64(entry.Uid)),
			"gid":         intObj(int64(entry.Gid)),
			"uname":       stringObj(entry.Uname),
			"gname":       stringObj(entry.Gname),
			"modified":    intObj(archiveUnix(entry.ModTime)),
			"accessed":    intObj(archiveUnix(entry.AccessTime)),
			"changed":     intObj(archiveUnix(entry.ChangeTime)),
			"is_dir":      boolObj(entry.Typeflag == tar.TypeDir),
			"unsafe_path": boolObj(unsafeTarMember(entry)),
		}))
	}

	return resultAndError(&object.Array{Elements: entries}, nil)
}

// TarRead reads one member as text, and TarReadBytes reads it as a buffer.
//
// Tar has no index, so a read walks the archive from the start until it reaches
// the member. On a plain .tar that walk is a seek per member and costs almost
// nothing; on a compressed one it means decompressing and discarding everything
// before it. Reading many members out of a large .tar.gz is therefore
// quadratic, and a program that wants most of an archive is better off
// decompressing it once to a plain .tar first.
func TarRead(args ...object.Object) object.Object {
	return tarRead(args, BuiltinNameTarRead, false)
}

func TarReadBytes(args ...object.Object) object.Object {
	return tarRead(args, BuiltinNameTarReadBytes, true)
}

// tarContentIndex returns the member whose body holds index's content.
//
// A regular file holds its own. A hard link has no body: it is the content of
// the member it names, the latest of that name written before it, which is
// what extracting the archive puts there. It used to read as an empty buffer
// with no error (M26-DAT-009). Anything else holds no content and is refused
// by what it is -- a symbolic link names the member to read instead.
func tarContentIndex(op string, entries []tarMember, index int) (int, *object.Error) {
	for {
		entry := entries[index]
		switch entry.Typeflag {
		case tar.TypeReg, tar.TypeCont, tar.TypeGNUSparse:
			return index, nil
		case tar.TypeDir:
			return 0, newError("%s: %q is a directory", op, entry.Name)
		case tar.TypeSymlink:
			return 0, newError("%s: %q is a symbolic link to %q, which holds no content of its own; read the member it names", op, entry.Name, entry.Linkname)
		case tar.TypeLink:
			target := -1
			for j := index - 1; j >= 0; j-- {
				if entries[j].Name == entry.Linkname {
					target = j
					break
				}
			}
			if target < 0 {
				return 0, newError("%s: %q is a hard link to %q, which no member before it holds", op, entry.Name, entry.Linkname)
			}
			index = target
		default:
			return 0, newError("%s: %q is a %s, which holds no content", op, entry.Name, tarEntryType(entry.Typeflag))
		}
	}
}

func tarRead(args []object.Object, opName string, binary bool) object.Object {
	if len(args) < 2 || len(args) > 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}

	state, errObj := resolveTarHandle(args[0], opName)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	names := make([]string, len(state.Entries))
	for i, entry := range state.Entries {
		names[i] = entry.Name
	}
	index, errObj := archiveMemberIndex(opName, state.Path, names, args[1])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	content, errObj := tarContentIndex(opName, state.Entries, index)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	name := state.Entries[index].Name

	// A tar member is stored uncompressed inside the stream, so there is no
	// per-member compressed size to derive a limit from; the whole archive's
	// size is the only input figure there is. It bounds every member, since no
	// member's compressed form can be larger than the archive containing it.
	limit, errObj := resolveDecompressionLimit(opName, args, 3, state.Size)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if size := state.Entries[content].Size; size > limit {
		return resultAndError(nil, newError("%s: %q declares %d bytes, past the %d-byte limit "+
			"(pass an explicit max_bytes to raise it)", opName, name, size, limit))
	}

	state.Mu.Lock()
	defer state.Mu.Unlock()

	stream, err := tarStream(state)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", opName, err.Error()))
	}
	defer stream.Close()

	reader := tar.NewReader(stream)
	for i := 0; ; i++ {
		header, err := reader.Next()
		if err == io.EOF {
			return resultAndError(nil, newError("%s: %s ends before member %d, which tar_open listed", opName, state.Path, content))
		}
		if err != nil {
			return resultAndError(nil, newError("%s: %s", opName, err.Error()))
		}
		if i < content {
			continue
		}
		if header.Name != state.Entries[content].Name {
			return resultAndError(nil, newError("%s: member %d of %s is %q now, not the %q tar_open listed; the archive changed under the handle",
				opName, content, state.Path, header.Name, state.Entries[content].Name))
		}
		data, err := readLimited(reader, limit)
		if err != nil {
			return resultAndError(nil, newError("%s: %s: %s", opName, name, err.Error()))
		}
		return resultAndError(binaryResult(binary, data), nil)
	}
}

// TarClose releases a handle and the archive file behind it.
func TarClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	handleObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `tar_close` must be STRING handle, got %s", args[0].Type()))
	}

	tarStore.Lock()
	state, exists := tarStore.handles[handleObj.Value]
	if exists {
		delete(tarStore.handles, handleObj.Value)
	}
	tarStore.Unlock()

	if !exists {
		return resultAndError(nil, newError("tar_close: unknown tar handle: %s", handleObj.Value))
	}

	custodyRecordTouch(BuiltinNameTarClose, handleObj.Value)

	if err := state.File.Close(); err != nil {
		return resultAndError(nil, newError("tar_close: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handleObj.Value),
		"closed": boolObj(true),
		"status": stringObj("ok"),
	}), nil)
}

func resolveTarHandle(arg object.Object, op string) (tarHandleState, *object.Error) {
	handleObj, ok := arg.(*object.String)
	if !ok {
		return tarHandleState{}, newError("argument 1 to `%s` must be STRING handle, got %s", op, arg.Type())
	}

	tarStore.RLock()
	state, exists := tarStore.handles[handleObj.Value]
	tarStore.RUnlock()
	if !exists {
		return tarHandleState{}, newError("%s: unknown tar handle: %s", op, handleObj.Value)
	}

	custodyRecordTouch(op, handleObj.Value)

	return state, nil
}
