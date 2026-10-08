package builtin

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"mutant/testkit"
)

// Each test pins one way the tar and zip readers answered wrongly without
// saying so -- a member read as empty, a name read as another member, a link
// judged from the wrong directory -- or could not be made to answer at all.
// Each fails on the code before its fix.

// M26-DAT-005. A .tar.zst decoder was never closed: its goroutines read the
// archive ahead of a read that had already returned, raced the next read's
// seek on the same file, and outlived tar_close. The leak is what fails here
// every time; the corrupted reads it caused came one or two in twenty.
func TestTarZstdReadsCloseTheirDecoders(t *testing.T) {
	testkit.CheckGoroutines(t)
	big := make([]byte, 2<<20)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	handle := openTar(t, writeTar(t, "zstd", []tarEntry{{name: "a.txt", body: []byte("first")}, {name: "big.bin", body: big}}))
	for i := 0; i < 20; i++ {
		if got := mustBytes(t, mustCall(t, TarReadBytes, handle, str("a.txt"))); string(got) != "first" {
			t.Fatalf("read %d of a.txt = %q", i, got)
		}
		if got := mustBytes(t, mustCall(t, TarReadBytes, handle, str("big.bin"))); !bytes.Equal(got, big) {
			t.Fatalf("read %d of big.bin differs from what was written", i)
		}
	}
}

// M26-DAT-006. A compressed walk stopped at 1000x the archive's size and
// nothing could raise it, so a collection that compresses past that -- here 16
// MiB of zeros under zstd -- could not be opened at all.
func TestTarOpenTakesAWalkLimit(t *testing.T) {
	path := writeTar(t, "zstd", []tarEntry{{name: "notes.txt", body: []byte("hello")}, {name: "zeros.img", body: make([]byte, 16<<20)}})
	errObj := callErr(t, TarOpen, str(path))
	if !strings.Contains(errObj.Message, "decompression limit exceeded") {
		t.Fatalf("by default: got %q, want the walk refused at its limit", errObj.Message)
	}
	handle := handleOf(t, mustCall(t, TarOpen, str(path), intObj(64<<20)))
	t.Cleanup(func() { TarClose(handle) })
	if got := mustBytes(t, mustCall(t, TarReadBytes, handle, str("notes.txt"))); string(got) != "hello" {
		t.Errorf("notes.txt = %q", got)
	}
}

// M26-DAT-007, tar. A symbolic link's target is read from the link's own
// directory, as an extractor reads it; read from the archive root, an ordinary
// root-filesystem link was flagged.
func TestTarUnsafePathReadsASymlinkFromItsOwnDirectory(t *testing.T) {
	ordinary := writeTar(t, "none", []tarEntry{
		{name: "usr/lib64/libfoo.so.1", body: []byte("lib")},
		{name: "usr/lib/libfoo.so", typeflag: tar.TypeSymlink, linkname: "../lib64/libfoo.so.1"},
	})
	opened := mustCall(t, TarOpen, str(ordinary))
	TarClose(handleOf(t, opened))
	if n := hashInt(t, opened, "unsafe_path_count"); n != 0 {
		t.Errorf("usr/lib/libfoo.so -> ../lib64/libfoo.so.1 counted as unsafe (%d)", n)
	}

	escaping := writeTar(t, "none", []tarEntry{{name: "a/b", typeflag: tar.TypeSymlink, linkname: "../../etc"}})
	opened = mustCall(t, TarOpen, str(escaping))
	TarClose(handleOf(t, opened))
	if n := hashInt(t, opened, "unsafe_path_count"); n != 1 {
		t.Errorf("a/b -> ../../etc counted %d unsafe, want 1", n)
	}
}

// M26-DAT-007, zip. A zip symbolic link carries its target as its body, and
// only names were checked: a link to /etc, and a file written through it,
// counted nothing.
func TestZipUnsafePathFollowsASymlinkEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "links.zip")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(file)
	for _, entry := range []struct {
		name, body string
		link       bool
	}{{"link", "/etc", true}, {"link/cron.d/evil", "* * * * * root sh", false}, {"lib/x.so", "../lib64/x.so", true}} {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store, Modified: time.Unix(1700000000, 0)}
		if entry.link {
			header.SetMode(os.ModeSymlink | 0o777)
		}
		part, err := w.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	file.Close()

	opened := mustCall(t, ZipOpen, str(path))
	handle := handleOf(t, opened)
	t.Cleanup(func() { ZipClose(handle) })
	if n := hashInt(t, opened, "unsafe_path_count"); n != 1 {
		t.Errorf("unsafe_path_count = %d, want 1: the link to /etc", n)
	}
	entries := mustArray(t, mustCall(t, ZipEntries, handle)).Elements
	for i, want := range []bool{true, false, false} {
		if got := hashBool(t, entries[i], "unsafe_path"); got != want {
			t.Errorf("%s: unsafe_path = %v, want %v", hashStr(t, entries[i], "name"), got, want)
		}
	}
}

// M26-DAT-008. A plain tar begins with its first member's name, and one
// beginning "BZh" was refused as broken bzip2.
func TestTarOpenReadsAPlainTarWhoseFirstNameLooksCompressed(t *testing.T) {
	path := writeTar(t, "none", []tarEntry{{name: "BZhistory.txt", body: []byte("shell history")}})
	opened := mustCall(t, TarOpen, str(path))
	handle := handleOf(t, opened)
	t.Cleanup(func() { TarClose(handle) })
	if got := hashStr(t, opened, "compression"); got != "none" {
		t.Errorf("compression = %q, want none", got)
	}
	if got := mustBytes(t, mustCall(t, TarReadBytes, handle, str("BZhistory.txt"))); string(got) != "shell history" {
		t.Errorf("BZhistory.txt = %q", got)
	}
}

// M26-DAT-009. A hard link has no body, and read as an empty buffer with no
// error; it is the member it names. A symbolic link, a device and a link to a
// member the archive does not hold are refused, each saying which.
func TestTarReadFollowsAHardLinkAndRefusesWhatHoldsNoContent(t *testing.T) {
	handle := openTar(t, writeTar(t, "none", []tarEntry{
		{name: "bin/tool", body: []byte("payload")},
		{name: "bin/tool2", typeflag: tar.TypeLink, linkname: "bin/tool"},
		{name: "bin/sh", typeflag: tar.TypeSymlink, linkname: "tool"},
		{name: "dev/null", typeflag: tar.TypeChar},
		{name: "bin/ghost", typeflag: tar.TypeLink, linkname: "bin/missing"},
	}))
	if got := mustBytes(t, mustCall(t, TarReadBytes, handle, str("bin/tool2"))); string(got) != "payload" {
		t.Errorf("the hard link bin/tool2 read as %q, want bin/tool's payload", got)
	}
	for name, want := range map[string]string{
		"bin/sh":    `symbolic link to "tool"`,
		"dev/null":  "char-device, which holds no content",
		"bin/ghost": `hard link to "bin/missing", which no member before it holds`,
	} {
		if errObj := callErr(t, TarReadBytes, handle, str(name)); !strings.Contains(errObj.Message, want) {
			t.Errorf("%s: got %q, want %q", name, errObj.Message, want)
		}
	}
}

// M26-DAT-010. A handle kept every *tar.Header, PAX records and all, which the
// docs called time rather than memory. It keeps the listing now, and the
// listing is bounded: names past 128 MiB in all are refused, here 135 members
// named a megabyte each.
func TestTarOpenBoundsTheListing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "long-names.tar.zst")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw, err := zstd.NewWriter(file)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	long := strings.Repeat("a", 1_000_000)
	for i := 0; i < 135; i++ {
		header := &tar.Header{Name: fmt.Sprintf("%s/%04d", long, i), Mode: 0o644, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	file.Close()

	errObj := callErr(t, TarOpen, str(path), intObj(1<<30))
	if !strings.Contains(errObj.Message, "run past 134217728 bytes") {
		t.Errorf("got %q, want the listing bound", errObj.Message)
	}
}

// Two members may share a name -- a tar appended to holds every version of a
// file -- and a read returned the first, the stale one, without a word. Such a
// name is refused, and each member is read by its position. A backslash
// spelling no longer reads another member that matches it only once rewritten.
func TestTarReadRefusesANameTwoMembersShare(t *testing.T) {
	handle := openTar(t, writeTar(t, "none", []tarEntry{
		{name: "a.txt", body: []byte("old")},
		{name: "x/y", body: []byte("slash")},
		{name: `x\y`, body: []byte("backslash")},
		{name: "a.txt", body: []byte("new")},
	}))
	if errObj := callErr(t, TarReadBytes, handle, str("a.txt")); !strings.Contains(errObj.Message, `more than one entry`) {
		t.Errorf("got %q, want the shared name refused", errObj.Message)
	}
	for position, want := range map[int64]string{0: "old", 3: "new"} {
		if got := mustBytes(t, mustCall(t, TarReadBytes, handle, intObj(position))); string(got) != want {
			t.Errorf("member %d = %q, want %q", position, got, want)
		}
	}
	if got := mustBytes(t, mustCall(t, TarReadBytes, handle, str(`x\y`))); string(got) != "backslash" {
		t.Errorf(`x\y read as %q, want its own content`, got)
	}
	if errObj := callErr(t, TarReadBytes, handle, intObj(4)); !strings.Contains(errObj.Message, "out of range") {
		t.Errorf("got %q", errObj.Message)
	}
}

func TestZipReadRefusesANameTwoEntriesShare(t *testing.T) {
	handle := openZip(t, writeZip(t, []zipEntry{{name: "a.txt", body: []byte("old")}, {name: "a.txt", body: []byte("new")}}))
	if errObj := callErr(t, ZipReadBytes, handle, str("a.txt")); !strings.Contains(errObj.Message, `more than one entry`) {
		t.Errorf("got %q, want the shared name refused", errObj.Message)
	}
	if got := mustBytes(t, mustCall(t, ZipReadBytes, handle, intObj(1))); string(got) != "new" {
		t.Errorf("entry 1 = %q, want new", got)
	}
}
