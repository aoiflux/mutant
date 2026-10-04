package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/builtin"
)

// TestTheVHDIExampleRunsOnAnImage runs examples/filesystem/vhdi_example.mut as
// shipped, against a small fixed VHD it finds where the example looks for one.
//
// The sweep marks the example needs-input and never runs it, so it failed on the
// first real image for as long as it had (M26-EX-020): it built its lines with
// `+`, and virtual_size is an integer. It also printed with no newline and gave
// the sector it read to putf as the format, so the sector here holds a `%`
// followed by verbs, and has to come back as it was written.
func TestTheVHDIExampleRunsOnAnImage(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	example, err := os.ReadFile(filepath.Join(root, "examples", "filesystem", "vhdi_example.mut"))
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, "vhdi_example.mut"), example, 0o644); err != nil {
		t.Fatal(err)
	}

	const sector = "100% sector zero %d %s"
	payload := make([]byte, 64*1024)
	copy(payload, sector)
	// libvhdi tells VHD from VHDX by content, so a fixed VHD answers to the name
	// the example opens.
	image := append(payload, fixedVHDFooter(uint64(len(payload)))...)
	if err := os.WriteFile(filepath.Join(work, "disk.vhdx"), image, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)

	var code int
	stderr := captureStderr(t, func() { code = run([]string{"mutant", "vhdi_example.mut", "--dev"}) })
	if code != 0 {
		t.Fatalf("the example did not compile (exit %d):\n%s", code, stderr)
	}
	var out bytes.Buffer
	restore := builtin.SetOutput(&out)
	stderr = captureStderr(t, func() { code = run([]string{"mutant", "vhdi_example.mu", "--dev"}) })
	restore()
	printed := out.String()
	if code != 0 {
		t.Fatalf("the example failed (exit %d)\nstdout:\n%s\nstderr:\n%s", code, printed, stderr)
	}

	for _, want := range []string{
		"VHDI opened: ./disk.vhdx (handle=vhdi-handle-",
		")\nMetadata:\n",
		"  format=VHD\n",
		"  virtual_size=65536\n",
		"  sector_size=512\n",
		"  is_differencing=false\n",
		"Offset map @0: mapped=true, file_offset=0\n",
		"Read first 512 logical bytes (string rendering):\n" + sector,
		"Handle closed: true\n",
	} {
		if !strings.Contains(printed, want) {
			t.Errorf("the example's output lacks %q\nstdout:\n%s", want, printed)
		}
	}
}

// fixedVHDFooter is the 512-byte footer that ends a fixed VHD, the same one
// builtin/disk_image_vhdfixture_test.go writes, for the one image this test
// needs. Only the fields a reader checks are filled in.
func fixedVHDFooter(size uint64) []byte {
	buf := make([]byte, 512)
	copy(buf[0:8], "conectix")
	binary.BigEndian.PutUint32(buf[8:12], 2)           // features: the reserved bit
	binary.BigEndian.PutUint32(buf[12:16], 0x00010000) // format version 1.0
	binary.BigEndian.PutUint64(buf[16:24], ^uint64(0)) // data offset: none, a fixed image
	copy(buf[28:32], "mtnt")
	binary.BigEndian.PutUint32(buf[32:36], 0x00010000)
	copy(buf[36:40], "Wi2k")
	binary.BigEndian.PutUint64(buf[40:48], size) // original size
	binary.BigEndian.PutUint64(buf[48:56], size) // current size
	// CHS for 128 sectors, as the specification derives it: 1 cylinder, 4
	// heads, 17 sectors a track.
	binary.BigEndian.PutUint16(buf[56:58], 1)
	buf[58], buf[59] = 4, 17
	binary.BigEndian.PutUint32(buf[60:64], 2) // disk type: fixed
	var sum uint32
	for i, b := range buf {
		if i < 64 || i >= 68 {
			sum += uint32(b)
		}
	}
	binary.BigEndian.PutUint32(buf[64:68], ^sum)
	return buf
}
