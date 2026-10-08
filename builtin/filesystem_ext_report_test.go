package builtin

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// buildExt2SparseFile is buildExt2Image's volume with its file made three
// blocks long and the middle one a hole: logical block 0 is block 8 and
// logical block 2 is block 9, so the two runs sit side by side on disk and
// 2048 bytes apart in the file.
func buildExt2SparseFile() []byte {
	const bs = 1024
	le := binary.LittleEndian
	img := buildExt2Image("sparse.bin", nil)
	file := img[5*bs+11*128 : 5*bs+12*128]
	le.PutUint32(file[4:], 3*bs)
	le.PutUint32(file[28:], 4) // two blocks, in 512-byte sectors
	le.PutUint32(file[40:], 8) // i_block[0]
	le.PutUint32(file[48:], 9) // i_block[2]; i_block[1] is the hole
	img[3*bs+1] |= 0x01        // block 9 in use
	copy(img[8*bs:9*bs], bytes.Repeat([]byte("A"), bs))
	copy(img[9*bs:10*bs], bytes.Repeat([]byte("C"), bs))
	return img
}

func extReportOf(t *testing.T, image []byte) *object.Hash {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.img")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	payload, errObj := unwrapPair(t, ExtOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("ext_open: %s", errObj.Inspect())
	}
	handle := mustHashValue(t, payload.(*object.Hash), "handle")
	t.Cleanup(func() { ExtClose(handle) })
	payload, errObj = unwrapPair(t, ExtReport(handle))
	if errObj != nil {
		t.Fatalf("ext_report: %s", errObj.Inspect())
	}
	return payload.(*object.Hash)
}

func reportRow(t *testing.T, report *object.Hash, path string) *object.Hash {
	t.Helper()
	for _, f := range mustHashArrayValue(t, report, "files") {
		if row := f.(*object.Hash); mustHashStringValue(t, row, "path") == path {
			return row
		}
	}
	t.Fatalf("the report has no row for %s: %s", path, report.Inspect())
	return nil
}

// TestAnExtReportRunSitsWhereTheFileHasIt is M26-FS1-012's regression test.
// libext's fragments end inclusively and carry no file offset; ext_report took
// each length as end - start, a byte short, and each file offset as the bytes
// before it, so the run after the hole was placed at byte 1023 of the file
// rather than 2048. Every other format's ends are exclusive, and so was none
// of ext's -- the volume's own end_offset included.
func TestAnExtReportRunSitsWhereTheFileHasIt(t *testing.T) {
	report := extReportOf(t, buildExt2SparseFile())
	if got := mustHashIntValue(t, report, "end_offset"); got != 64*1024 {
		t.Errorf("the volume's end_offset is %d, want 65536: one past its last byte", got)
	}
	row := reportRow(t, report, "/sparse.bin")
	want := [][3]int64{{8 * 1024, 9 * 1024, 0}, {9 * 1024, 10 * 1024, 2048}} // start, end, file offset
	fragments := mustHashArrayValue(t, row, "fragments")
	if len(fragments) != len(want) {
		t.Fatalf("%d fragments, want %d: %s", len(fragments), len(want), row.Inspect())
	}
	for i, f := range fragments {
		fragment := f.(*object.Hash)
		got := [3]int64{mustHashIntValue(t, fragment, "start_offset"), mustHashIntValue(t, fragment,
			"end_offset"), mustHashIntValue(t, fragment, "file_offset")}
		if got != want[i] || mustHashIntValue(t, fragment, "length") != 1024 {
			t.Errorf("fragment %d is %v length %d, want %v length 1024", i, got,
				mustHashIntValue(t, fragment, "length"), want[i])
		}
	}
	if covered := mustHashIntValue(t, mustHashValue(t, row, "layout").(*object.Hash), "bytes_covered"); covered != 2048 {
		t.Errorf("bytes_covered = %d, want 2048", covered)
	}
}

// TestAnExtFileWhoseMapCannotBeReadIsNotALocatedFile is M26-FS1-013's
// regression test: the file is flagged extent-mapped and its i_block holds no
// extent header. libext keeps the row with no fragments and a degraded_read
// warning; ext_report never read the warnings, so the row looked like a file
// with nothing to locate and the report said complete.
func TestAnExtFileWhoseMapCannotBeReadIsNotALocatedFile(t *testing.T) {
	image := buildExt2Image("hello.txt", []byte("hi\n"))
	file := image[5*1024+11*128 : 5*1024+12*128]
	binary.LittleEndian.PutUint32(file[0x20:], 0x80000) // EXT4_EXTENTS_FL

	report := extReportOf(t, image)
	if mustHashBoolValue(t, report, "complete") {
		t.Errorf("a report with a file whose map could not be read says complete")
	}
	layout := mustHashValue(t, reportRow(t, report, "/hello.txt"), "layout").(*object.Hash)
	if mustHashStringValue(t, layout, "error") == "" {
		t.Errorf("the row's layout gives no error: %s", layout.Inspect())
	}
	codes := hashWarningCodes(t, report)
	if !hasCode(codes, fsReportWarnLayoutFailed) || !hasCode(codes, "degraded_read") {
		t.Errorf("the report's warning codes %v do not carry the failure", codes)
	}
}

// TestAnExtReportOfATableCutShortIsNotComplete: the inode table moved to the
// image's last block, so inodes 9-16 lie past its end. libext's deep walk
// passes over an inode it cannot read without a warning, so their rows were
// missing from a report that said it was complete.
func TestAnExtReportOfATableCutShortIsNotComplete(t *testing.T) {
	const bs = 1024
	image := buildExt2DeletedInode(false)
	copy(image[63*bs:64*bs], image[5*bs:6*bs])
	binary.LittleEndian.PutUint32(image[2*bs+8:], 63) // the group's inode table

	report := extReportOf(t, image)
	if mustHashBoolValue(t, report, "complete") {
		t.Errorf("a report that could not read 8 inodes says complete: %s", report.Inspect())
	}
	if reason := mustHashStringValue(t, report, "incomplete_reason"); !strings.Contains(reason, "past the end of the image") {
		t.Errorf("incomplete_reason does not name the unread slots: %q", reason)
	}
}
