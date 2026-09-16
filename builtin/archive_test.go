package builtin

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"mutant/object"
)

// The archive builtins are the language's first readers of a container that is
// itself hostile input, so these tests are as interested in what the family
// refuses as in what it reads.

// callPair invokes a builtin and splits the (value, err) pair it returns.
func callPair(t *testing.T, fn func(...object.Object) object.Object, args ...object.Object) (object.Object, *object.Error) {
	t.Helper()

	multi, ok := fn(args...).(*object.MultiValue)
	if !ok {
		t.Fatalf("builtin did not return a (value, err) pair")
	}
	if len(multi.Values) != 2 {
		t.Fatalf("pair has %d values, want 2", len(multi.Values))
	}
	if errObj, ok := multi.Values[1].(*object.Error); ok {
		return multi.Values[0], errObj
	}
	return multi.Values[0], nil
}

func mustCall(t *testing.T, fn func(...object.Object) object.Object, args ...object.Object) object.Object {
	t.Helper()

	value, errObj := callPair(t, fn, args...)
	if errObj != nil {
		t.Fatalf("call failed: %s", errObj.Message)
	}
	return value
}

func handleOf(t *testing.T, opened object.Object) *object.String {
	t.Helper()

	handle, ok := hashField(t, opened, "handle").(*object.String)
	if !ok {
		t.Fatal("handle is not a STRING")
	}
	return handle
}

// zipEntry is one member to write into a test archive.
type zipEntry struct {
	name   string
	body   []byte
	method uint16
}

func writeZip(t *testing.T, entries []zipEntry) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "evidence.zip")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %s", err)
	}
	defer file.Close()

	w := zip.NewWriter(file)
	w.RegisterCompressor(93, func(out io.Writer) (io.WriteCloser, error) {
		return zstd.NewWriter(out)
	})
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: entry.method, Modified: time.Unix(1700000000, 0)}
		part, err := w.CreateHeader(header)
		if err != nil {
			t.Fatalf("create %q: %s", entry.name, err)
		}
		if _, err := part.Write(entry.body); err != nil {
			t.Fatalf("write %q: %s", entry.name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close zip: %s", err)
	}
	return path
}

func openZip(t *testing.T, path string) *object.String {
	t.Helper()

	opened := mustCall(t, ZipOpen, &object.String{Value: path})
	handle := handleOf(t, opened)
	t.Cleanup(func() { ZipClose(handle) })
	return handle
}

func TestZipReadsEntriesInEveryMethodItRegisters(t *testing.T) {
	body := bytes.Repeat([]byte("evidence\x00\xff"), 64)
	path := writeZip(t, []zipEntry{
		{name: "stored.bin", body: body, method: zip.Store},
		{name: "deflated.bin", body: body, method: zip.Deflate},
		{name: "zstd.bin", body: body, method: 93},
	})

	handle := openZip(t, path)

	for _, name := range []string{"stored.bin", "deflated.bin", "zstd.bin"} {
		got := mustCall(t, ZipReadBytes, handle, &object.String{Value: name})
		buf, ok := got.(*object.Bytes)
		if !ok {
			t.Fatalf("%s came back as %s, want BYTES", name, got.Type())
		}
		if !bytes.Equal(buf.Value, body) {
			t.Errorf("%s round-tripped to %d bytes, want %d", name, len(buf.Value), len(body))
		}
	}

	// zstd is not one of archive/zip's own methods. Reading it at all is what
	// proves registerZipDecompressors ran on the reader the handle holds.
	text := mustCall(t, ZipRead, handle, &object.String{Value: "zstd.bin"})
	if _, ok := text.(*object.String); !ok {
		t.Errorf("zip_read returned %s, want STRING", text.Type())
	}
	if text.Inspect() != string(body) {
		t.Error("zip_read and zip_read_bytes disagree about the same entry")
	}
}

func TestZipEntriesDescribesWithoutDecompressing(t *testing.T) {
	body := bytes.Repeat([]byte("a"), 4096)
	path := writeZip(t, []zipEntry{{name: "logs/app.log", body: body, method: zip.Deflate}})

	handle := openZip(t, path)
	listed := mustCall(t, ZipEntries, handle)

	array, ok := listed.(*object.Array)
	if !ok {
		t.Fatalf("zip_entries returned %s, want ARRAY", listed.Type())
	}
	if len(array.Elements) != 1 {
		t.Fatalf("listed %d entries, want 1", len(array.Elements))
	}

	entry := array.Elements[0]
	if got := hashField(t, entry, "name").Inspect(); got != "logs/app.log" {
		t.Errorf("name = %q", got)
	}
	if got := hashField(t, entry, "size").Inspect(); got != "4096" {
		t.Errorf("size = %s, want 4096", got)
	}
	if got := hashField(t, entry, "method").Inspect(); got != "deflate" {
		t.Errorf("method = %s, want deflate", got)
	}
	if got := hashField(t, entry, "unsafe_path").Inspect(); got != "false" {
		t.Errorf("unsafe_path = %s for an ordinary name", got)
	}
	// A 4 KiB run of one byte must have actually compressed, or the entry says
	// nothing about whether compressed_size is real.
	compressed := hashField(t, entry, "compressed_size").(*object.Integer).Value
	if compressed <= 0 || compressed >= 4096 {
		t.Errorf("compressed_size = %d, want a real compressed figure under 4096", compressed)
	}
}

func TestZipRefusesWhatItCannotRead(t *testing.T) {
	path := writeZip(t, []zipEntry{
		{name: "dir/", body: nil, method: zip.Store},
		{name: "dir/file.txt", body: []byte("hello"), method: zip.Deflate},
	})
	handle := openZip(t, path)

	for _, tt := range []struct {
		name string
		args []object.Object
		want string
	}{
		{"missing entry", []object.Object{handle, &object.String{Value: "nope.txt"}}, "no entry named"},
		{"a directory", []object.Object{handle, &object.String{Value: "dir/"}}, "is a directory"},
		{"unknown handle", []object.Object{&object.String{Value: "zip-handle-9999"}, &object.String{Value: "x"}}, "unknown zip handle"},
		{"handle is not a string", []object.Object{&object.Integer{Value: 1}, &object.String{Value: "x"}}, "must be STRING handle"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, errObj := callPair(t, ZipRead, tt.args...)
			if errObj == nil {
				t.Fatal("call succeeded, want an error")
			}
			if !strings.Contains(errObj.Message, tt.want) {
				t.Errorf("error = %q, want it to mention %q", errObj.Message, tt.want)
			}
		})
	}
}

// A zip written on Windows can store backslashes even though the format says
// otherwise, so a name is matched both ways.
func TestZipFindsAnEntryWrittenWithBackslashes(t *testing.T) {
	path := writeZip(t, []zipEntry{{name: `Users\analyst\NTUSER.DAT`, body: []byte("hive"), method: zip.Store}})
	handle := openZip(t, path)

	for _, name := range []string{`Users\analyst\NTUSER.DAT`, "Users/analyst/NTUSER.DAT"} {
		if got := mustCall(t, ZipRead, handle, &object.String{Value: name}); got.Inspect() != "hive" {
			t.Errorf("%q read back as %q", name, got.Inspect())
		}
	}
}

// tarEntry is one member to write into a test archive.
type tarEntry struct {
	name     string
	body     []byte
	typeflag byte
	linkname string
}

// writeTar builds a tar and optionally wraps it, so the same members can be
// presented to tar_open in every container form it claims to detect.
func writeTar(t *testing.T, compression string, entries []tarEntry) string {
	t.Helper()

	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, entry := range entries {
		flag := entry.typeflag
		if flag == 0 {
			flag = tar.TypeReg
		}
		header := &tar.Header{
			Name:     entry.name,
			Size:     int64(len(entry.body)),
			Mode:     0o644,
			Typeflag: flag,
			Linkname: entry.linkname,
			Uid:      1000,
			Gid:      1000,
			Uname:    "analyst",
			Gname:    "staff",
			ModTime:  time.Unix(1700000000, 0),
		}
		if flag != tar.TypeReg {
			header.Size = 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("header %q: %s", entry.name, err)
		}
		if flag == tar.TypeReg {
			if _, err := tw.Write(entry.body); err != nil {
				t.Fatalf("write %q: %s", entry.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %s", err)
	}

	var wrapped bytes.Buffer
	switch compression {
	case "none":
		wrapped = raw
	case "gzip":
		gw := gzip.NewWriter(&wrapped)
		if _, err := gw.Write(raw.Bytes()); err != nil {
			t.Fatalf("gzip: %s", err)
		}
		if err := gw.Close(); err != nil {
			t.Fatalf("gzip close: %s", err)
		}
	case "zstd":
		zw, err := zstd.NewWriter(&wrapped)
		if err != nil {
			t.Fatalf("zstd: %s", err)
		}
		if _, err := zw.Write(raw.Bytes()); err != nil {
			t.Fatalf("zstd write: %s", err)
		}
		if err := zw.Close(); err != nil {
			t.Fatalf("zstd close: %s", err)
		}
	default:
		t.Fatalf("unknown compression %q", compression)
	}

	path := filepath.Join(t.TempDir(), "collection.tar")
	if err := os.WriteFile(path, wrapped.Bytes(), 0o600); err != nil {
		t.Fatalf("write: %s", err)
	}
	return path
}

func openTar(t *testing.T, path string) *object.String {
	t.Helper()

	opened := mustCall(t, TarOpen, &object.String{Value: path})
	handle := handleOf(t, opened)
	t.Cleanup(func() { TarClose(handle) })
	return handle
}

// The container is detected by magic, not by extension: every archive these
// cases write is named .tar whatever is actually wrapping it.
func TestTarDetectsItsCompressionFromContent(t *testing.T) {
	body := bytes.Repeat([]byte("\x00\xffsyslog"), 128)

	for _, compression := range []string{"none", "gzip", "zstd"} {
		t.Run(compression, func(t *testing.T) {
			path := writeTar(t, compression, []tarEntry{{name: "var/log/syslog", body: body}})

			opened := mustCall(t, TarOpen, &object.String{Value: path})
			handle := handleOf(t, opened)
			defer TarClose(handle)

			if got := hashField(t, opened, "compression").Inspect(); got != compression {
				t.Errorf("compression = %s, want %s", got, compression)
			}
			if got := hashField(t, opened, "entry_count").Inspect(); got != "1" {
				t.Errorf("entry_count = %s, want 1", got)
			}

			read := mustCall(t, TarReadBytes, handle, &object.String{Value: "var/log/syslog"})
			buf, ok := read.(*object.Bytes)
			if !ok {
				t.Fatalf("tar_read_bytes returned %s, want BYTES", read.Type())
			}
			if !bytes.Equal(buf.Value, body) {
				t.Errorf("member came back as %d bytes, want %d", len(buf.Value), len(body))
			}
		})
	}
}

func TestTarEntriesCarriesPosixMetadata(t *testing.T) {
	path := writeTar(t, "gzip", []tarEntry{
		{name: "etc/", typeflag: tar.TypeDir},
		{name: "etc/passwd", body: []byte("root:x:0:0")},
		{name: "etc/shadow.link", typeflag: tar.TypeSymlink, linkname: "shadow"},
	})

	listed := mustCall(t, TarEntries, openTar(t, path))
	array, ok := listed.(*object.Array)
	if !ok {
		t.Fatalf("tar_entries returned %s, want ARRAY", listed.Type())
	}
	if len(array.Elements) != 3 {
		t.Fatalf("listed %d members, want 3", len(array.Elements))
	}

	byType := map[string]object.Object{}
	for _, entry := range array.Elements {
		byType[hashField(t, entry, "type").Inspect()] = entry
	}
	for _, want := range []string{"dir", "file", "symlink"} {
		if _, ok := byType[want]; !ok {
			t.Fatalf("no member of type %s; got %v", want, byType)
		}
	}

	file := byType["file"]
	if got := hashField(t, file, "uname").Inspect(); got != "analyst" {
		t.Errorf("uname = %s", got)
	}
	if got := hashField(t, file, "gid").Inspect(); got != "1000" {
		t.Errorf("gid = %s", got)
	}
	if got := hashField(t, file, "modified").Inspect(); got != "1700000000" {
		t.Errorf("modified = %s", got)
	}
	if got := hashField(t, byType["symlink"], "linkname").Inspect(); got != "shadow" {
		t.Errorf("linkname = %s", got)
	}
	if got := hashField(t, byType["dir"], "is_dir").Inspect(); got != "true" {
		t.Errorf("dir is_dir = %s", got)
	}
}

func TestTarRefusesWhatItCannotRead(t *testing.T) {
	path := writeTar(t, "none", []tarEntry{
		{name: "etc/", typeflag: tar.TypeDir},
		{name: "etc/passwd", body: []byte("root:x:0:0")},
	})
	handle := openTar(t, path)

	for _, tt := range []struct {
		name string
		args []object.Object
		want string
	}{
		{"missing member", []object.Object{handle, &object.String{Value: "nope"}}, "no entry named"},
		{"a directory", []object.Object{handle, &object.String{Value: "etc/"}}, "is a directory"},
		{"unknown handle", []object.Object{&object.String{Value: "tar-handle-9999"}, &object.String{Value: "x"}}, "unknown tar handle"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, errObj := callPair(t, TarRead, tt.args...); errObj == nil {
				t.Fatal("call succeeded, want an error")
			} else if !strings.Contains(errObj.Message, tt.want) {
				t.Errorf("error = %q, want it to mention %q", errObj.Message, tt.want)
			}
		})
	}
}

// Reads re-walk the archive from the start, so the second read of a handle has
// to work as well as the first. This is the case a seek left un-rewound breaks.
func TestTarReadsTheSameHandleRepeatedly(t *testing.T) {
	path := writeTar(t, "gzip", []tarEntry{
		{name: "a.txt", body: []byte("alpha")},
		{name: "b.txt", body: []byte("bravo")},
	})
	handle := openTar(t, path)

	for round := 0; round < 3; round++ {
		for name, want := range map[string]string{"a.txt": "alpha", "b.txt": "bravo"} {
			if got := mustCall(t, TarRead, handle, &object.String{Value: name}); got.Inspect() != want {
				t.Fatalf("round %d: %s = %q, want %q", round, name, got.Inspect(), want)
			}
		}
	}
}

func TestUnsafeArchivePath(t *testing.T) {
	for _, tt := range []struct {
		name string
		want bool
	}{
		{"logs/app.log", false},
		{"a/b/../c.txt", false}, // climbs, but not out
		{"", false},
		{"..", true},
		{"../etc/passwd", true},
		{"a/../../etc/passwd", true},
		{"/etc/passwd", true},
		{"//server/share/x", true},
		{`C:\Windows\System32\config\SAM`, true},
		{`..\..\Windows\System32`, true},
	} {
		if got := unsafeArchivePath(tt.name); got != tt.want {
			t.Errorf("unsafeArchivePath(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// Nothing here extracts, so a traversing name cannot be exploited through these
// builtins. It is reported because an archive that contains one is a finding:
// somebody built a container meant to write outside wherever it was unpacked.
func TestArchivesReportTraversingNamesWithoutActingOnThem(t *testing.T) {
	t.Run("zip", func(t *testing.T) {
		path := writeZip(t, []zipEntry{
			{name: "safe.txt", body: []byte("ok"), method: zip.Store},
			{name: "../../evil.txt", body: []byte("pwn"), method: zip.Store},
		})

		opened := mustCall(t, ZipOpen, &object.String{Value: path})
		handle := handleOf(t, opened)
		defer ZipClose(handle)

		if got := hashField(t, opened, "unsafe_path_count").Inspect(); got != "1" {
			t.Errorf("unsafe_path_count = %s, want 1", got)
		}

		flagged := map[string]string{}
		for _, entry := range mustCall(t, ZipEntries, handle).(*object.Array).Elements {
			flagged[hashField(t, entry, "name").Inspect()] = hashField(t, entry, "unsafe_path").Inspect()
		}
		if flagged["../../evil.txt"] != "true" || flagged["safe.txt"] != "false" {
			t.Errorf("unsafe_path flags = %v", flagged)
		}

		// The entry is still readable: reporting it is not refusing it, because
		// reading it into a buffer is exactly how an analyst examines it.
		if got := mustCall(t, ZipRead, handle, &object.String{Value: "../../evil.txt"}); got.Inspect() != "pwn" {
			t.Errorf("traversing entry read back as %q", got.Inspect())
		}
	})

	// A tar link target is the half of this that gets forgotten: the member's
	// own name is harmless and the symlink it creates is what escapes.
	t.Run("tar link target", func(t *testing.T) {
		path := writeTar(t, "none", []tarEntry{
			{name: "innocent", typeflag: tar.TypeSymlink, linkname: "../../../etc/shadow"},
		})

		opened := mustCall(t, TarOpen, &object.String{Value: path})
		handle := handleOf(t, opened)
		defer TarClose(handle)

		if got := hashField(t, opened, "unsafe_path_count").Inspect(); got != "1" {
			t.Errorf("unsafe_path_count = %s, want 1", got)
		}
		entry := mustCall(t, TarEntries, handle).(*object.Array).Elements[0]
		if got := hashField(t, entry, "unsafe_path").Inspect(); got != "true" {
			t.Errorf("unsafe_path = %s for a link target that escapes", got)
		}
	})
}

func TestDecompressionLimitDerivation(t *testing.T) {
	for _, tt := range []struct {
		name       string
		compressed int64
		want       int64
	}{
		{"unknown input size falls back to the ceiling", 0, maxDecompressedBytes},
		{"negative is treated as unknown", -1, maxDecompressedBytes},
		{"small input is bounded by the ratio", 1000, 1000 * maxDecompressionRatio},
		{"large input is bounded by the ceiling", maxDecompressedBytes, maxDecompressedBytes},
		// At the crossover the ratio still decides, and gives a figure just
		// under the ceiling; the ceiling takes over one byte later.
		{"exactly at the crossover", maxDecompressedBytes / maxDecompressionRatio, (maxDecompressedBytes / maxDecompressionRatio) * maxDecompressionRatio},
		{"one byte past the crossover", maxDecompressedBytes/maxDecompressionRatio + 1, maxDecompressedBytes},
	} {
		if got := decompressionLimit(tt.compressed); got != tt.want {
			t.Errorf("%s: decompressionLimit(%d) = %d, want %d", tt.name, tt.compressed, got, tt.want)
		}
	}
}

// readLimited is the guard that does not trust a declared size, so it is tested
// against the boundary rather than only against something obviously too big.
func TestReadLimitedStopsOneByteOver(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 100)

	if got, err := readLimited(bytes.NewReader(payload), 100); err != nil || len(got) != 100 {
		t.Errorf("exactly at the limit: %d bytes, err %v", len(got), err)
	}
	if got, err := readLimited(bytes.NewReader(payload), 101); err != nil || len(got) != 100 {
		t.Errorf("under the limit: %d bytes, err %v", len(got), err)
	}
	_, err := readLimited(bytes.NewReader(payload), 99)
	if err == nil {
		t.Fatal("one byte over the limit was accepted")
	}
	if !strings.Contains(err.Error(), "max_bytes") {
		t.Errorf("error %q does not say how to raise the limit", err)
	}
}

func TestCappedReaderNamesTheLimitRatherThanEndingCleanly(t *testing.T) {
	r := newCappedReader(bytes.NewReader(bytes.Repeat([]byte("y"), 100)), 10)

	n, err := io.ReadFull(r, make([]byte, 10))
	if n != 10 || err != nil {
		t.Fatalf("first 10 bytes: n=%d err=%v", n, err)
	}

	// The point of the type: past its budget it reports the limit instead of
	// the io.EOF a LimitReader would give, which a caller cannot tell from a
	// truncated archive.
	_, err = r.Read(make([]byte, 1))
	if err == nil || err == io.EOF {
		t.Fatalf("read past the cap returned %v, want a limit error", err)
	}
	if !strings.Contains(err.Error(), "expands past") {
		t.Errorf("error = %q", err)
	}
}

// The two limits are enforced at different moments and both have to hold.
//
// A zip declares an uncompressed size in its central directory, which lets an
// oversized entry be rejected before a byte is decompressed -- but the declared
// size is written by whoever built the archive, so it is a fast path and not
// the guarantee. gunzip has no declared size at all, which makes it the honest
// test of the read-time guard: nothing there can refuse the stream except
// watching what comes out of it.
func TestExplicitMaxBytesIsEnforcedByBothGuards(t *testing.T) {
	body := bytes.Repeat([]byte("a"), 1000)

	t.Run("zip rejects on the declared size", func(t *testing.T) {
		handle := openZip(t, writeZip(t, []zipEntry{{name: "big.bin", body: body, method: zip.Deflate}}))

		_, errObj := callPair(t, ZipRead, handle, &object.String{Value: "big.bin"}, &object.Integer{Value: 10})
		if errObj == nil {
			t.Fatal("a 1000-byte entry was read under a 10-byte limit")
		}
		if !strings.Contains(errObj.Message, "declares 1000 bytes") {
			t.Errorf("error = %q, want it to name the declared size", errObj.Message)
		}
		if !strings.Contains(errObj.Message, "max_bytes") {
			t.Errorf("error = %q, want it to say how to raise the limit", errObj.Message)
		}

		// Exactly at the limit is allowed: the check is "past", not "at".
		if got := mustCall(t, ZipReadBytes, handle, &object.String{Value: "big.bin"}, &object.Integer{Value: 1000}); len(got.(*object.Bytes).Value) != 1000 {
			t.Error("an entry exactly at its limit was refused")
		}
	})

	t.Run("gunzip rejects on what actually comes out", func(t *testing.T) {
		var compressed bytes.Buffer
		gw := gzip.NewWriter(&compressed)
		if _, err := gw.Write(body); err != nil {
			t.Fatalf("gzip: %s", err)
		}
		if err := gw.Close(); err != nil {
			t.Fatalf("gzip close: %s", err)
		}
		payload := &object.Bytes{Value: compressed.Bytes()}

		_, errObj := callPair(t, GunzipBytes, payload, &object.Integer{Value: 10})
		if errObj == nil {
			t.Fatal("1000 bytes of gzip output were accepted under a 10-byte limit")
		}
		if !strings.Contains(errObj.Message, "expands past 10 bytes") {
			t.Errorf("error = %q", errObj.Message)
		}

		// The default limit still lets ordinary data through, which is the
		// regression this cap could most easily have caused.
		got := mustCall(t, GunzipBytes, payload)
		if !bytes.Equal(got.(*object.Bytes).Value, body) {
			t.Error("ordinary gzip data no longer round-trips under the default limit")
		}
	})

	t.Run("a limit must be a positive count", func(t *testing.T) {
		handle := openZip(t, writeZip(t, []zipEntry{{name: "x", body: body, method: zip.Store}}))
		for _, bad := range []int64{0, -1} {
			_, errObj := callPair(t, ZipRead, handle, &object.String{Value: "x"}, &object.Integer{Value: bad})
			if errObj == nil {
				t.Fatalf("max_bytes=%d was accepted", bad)
			}
			if !strings.Contains(errObj.Message, "positive byte limit") {
				t.Errorf("max_bytes=%d: error = %q", bad, errObj.Message)
			}
		}
	})
}

// A closed handle is gone: the second close reports an unknown handle rather
// than closing an already-closed file, and the reads that follow fail too.
func TestClosingAnArchiveReleasesItsHandle(t *testing.T) {
	zipHandle := handleOf(t, mustCall(t, ZipOpen, &object.String{
		Value: writeZip(t, []zipEntry{{name: "a", body: []byte("x"), method: zip.Store}}),
	}))
	tarHandle := handleOf(t, mustCall(t, TarOpen, &object.String{
		Value: writeTar(t, "gzip", []tarEntry{{name: "a", body: []byte("x")}}),
	}))

	mustCall(t, ZipClose, zipHandle)
	mustCall(t, TarClose, tarHandle)

	if _, errObj := callPair(t, ZipClose, zipHandle); errObj == nil {
		t.Error("closing a zip handle twice succeeded")
	}
	if _, errObj := callPair(t, TarClose, tarHandle); errObj == nil {
		t.Error("closing a tar handle twice succeeded")
	}
	if _, errObj := callPair(t, ZipEntries, zipHandle); errObj == nil {
		t.Error("a closed zip handle still lists entries")
	}
	if _, errObj := callPair(t, TarEntries, tarHandle); errObj == nil {
		t.Error("a closed tar handle still lists entries")
	}
}

// An xz-wrapped tar is recognised so the failure names the format, rather than
// being reported as an unreadable archive.
func TestTarNamesXzRatherThanFailingObscurely(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collection.tar")
	if err := os.WriteFile(path, append([]byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, make([]byte, 64)...), 0o600); err != nil {
		t.Fatalf("write: %s", err)
	}

	_, errObj := callPair(t, TarOpen, &object.String{Value: path})
	if errObj == nil {
		t.Fatal("an xz archive opened")
	}
	if !strings.Contains(errObj.Message, "xz") {
		t.Errorf("error = %q, want it to name the format", errObj.Message)
	}
}
